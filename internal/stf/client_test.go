package stf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDevices(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"devices":[
			{"serial":"U1","name":"iPhone_15","node":"build-ua","present":true,"ready":true,"using":false,"provider":{"name":"mcloud-linux_S1_E1"},"owner":null},
			{"serial":"S2","name":"Pixel","node":"build-demo","present":true,"ready":true,"using":false,"provider":{"name":"mcloud-demo"},"owner":{"email":"qa@example.com","name":"qa"}}]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "tok")
	got, err := c.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if d := got["U1"]; d.Node != "build-ua" || d.Location != "S1_E1" || d.Busy || d.Name != "iPhone_15" {
		t.Errorf("U1: %+v", d)
	}
	if d := got["S2"]; d.Location != "" || !d.Busy || d.Owner != "qa@example.com" {
		t.Errorf("S2: %+v", d)
	}
	if _, _ = c.Devices(); calls != 1 {
		t.Errorf("not cached: %d calls", calls)
	}
	if _, err := New(srv.URL, "bad").Devices(); err == nil {
		t.Error("a refused token")
	}
	var none *Client
	if d, err := none.Devices(); d != nil || err != nil {
		t.Error("a nil client")
	}
}
