package headwind

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// the default admin password of the MQTT broker built into Headwind MDM (NotificationMqttConfigModule)
const defaultMQTTAdminPassword = "dd3V5YDkrX"

// runEntrypoint runs android/hmdm-entrypoint.sh on the template of testdata with env; the context it writes (empty
// when it fails), its output and whether it succeeded
func runEntrypoint(t *testing.T, env map[string]string) (string, string, bool) {
	t.Helper()
	dir := t.TempDir()
	context := filepath.Join(dir, "localhost")
	next := filepath.Join(dir, "next.sh")
	if err := os.WriteFile(next, []byte("#!/bin/sh\necho next\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	template, err := filepath.Abs("testdata/context_template.xml")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "../../android/hmdm-entrypoint.sh")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HMDM_ENTRYPOINT_TEMPLATE=" + template,
		"HMDM_ENTRYPOINT_CONTEXT=" + context, "HMDM_ENTRYPOINT_NEXT=" + next}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	raw, _ := os.ReadFile(filepath.Join(context, "ROOT.xml"))
	return string(raw), string(out), err == nil
}

func entrypointEnv() map[string]string {
	return map[string]string{
		"HMDM_PUBLIC_URL": "https://mcloud.example.com/hmdm", "SHARED_SECRET": "s3cr3t0123456789abcd",
		"SQL_HOST": "postgres", "SQL_BASE": "hmdm", "SQL_USER": "hmdm", "SQL_PASS": "pass",
		"HMDM_MQTT_ADMIN_PASSWORD": "Adm1nPassw0rdOfTheBroker",
	}
}

func TestEntrypointWritesTheMQTTAdminPassword(t *testing.T) {
	ctx, out, ok := runEntrypoint(t, entrypointEnv())
	if !ok {
		t.Fatalf("the entrypoint failed: %s", out)
	}
	for _, want := range []string{
		`<Parameter name="mqtt.auth" value="1"/>`,
		`<Parameter name="mqtt.admin.password" value="Adm1nPassw0rdOfTheBroker"/>`,
		`<Parameter name="secure.enrollment" value="1"/>`,
		`<Parameter name="base.url" value="https://mcloud.example.com/hmdm"/>`,
		`<Parameter name="hash.secret" value="s3cr3t0123456789abcd"/>`,
	} {
		if !strings.Contains(ctx, want) {
			t.Errorf("the context has no %s:\n%s", want, ctx)
		}
	}
	if strings.Count(ctx, `name="mqtt.admin.password"`) != 1 {
		t.Errorf("one mqtt.admin.password expected:\n%s", ctx)
	}
	if strings.Contains(out, "Adm1nPassw0rdOfTheBroker") || strings.Contains(ctx, defaultMQTTAdminPassword) {
		t.Errorf("the password is logged or the default one is there: %s", out)
	}
	if !strings.Contains(out, "next") {
		t.Errorf("the entrypoint of the image did not run: %s", out)
	}
}

func TestEntrypointRefusesNoOrAWeakMQTTAdminPassword(t *testing.T) {
	for name, password := range map[string]string{"empty": "", "short": "abc123", "not alphanumeric": "abcdefgh|ijklmnop1"} {
		env := entrypointEnv()
		env["HMDM_MQTT_ADMIN_PASSWORD"] = password
		ctx, out, ok := runEntrypoint(t, env)
		if ok || ctx != "" || strings.Contains(out, "next") {
			t.Errorf("%s: the entrypoint went on (%s)", name, out)
		}
	}
}

func TestEntrypointRefusesATemplateWithoutMQTTAuth(t *testing.T) {
	raw, err := os.ReadFile("testdata/context_template.xml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	template := filepath.Join(dir, "template.xml")
	if err := os.WriteFile(template, []byte(strings.ReplaceAll(string(raw), `name="mqtt.auth"`, `name="mqtt.other"`)), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "../../android/hmdm-entrypoint.sh")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HMDM_ENTRYPOINT_TEMPLATE=" + template,
		"HMDM_ENTRYPOINT_CONTEXT=" + filepath.Join(dir, "localhost"), "HMDM_ENTRYPOINT_NEXT=/bin/true"}
	for k, v := range entrypointEnv() {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "mqtt.auth is not in") {
		t.Fatalf("a template without mqtt.auth is accepted: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "localhost", "ROOT.xml")); err == nil {
		t.Fatal("a context without the admin password of the broker is written")
	}
}
