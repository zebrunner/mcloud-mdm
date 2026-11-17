#!/bin/bash
# shellcheck disable=SC2034
# The settings and the checks of the project for tests/lint.sh (CONVENTIONS.md): mcloud-mdm, a Go program.

scripts=(tests/*.sh android/*.sh)
dockerfiles=(Dockerfile android/agent/Dockerfile)
tools=(go)
# go_sources: the Go files of the repository
go_sources() {
  find cmd internal -name '*.go'
}
# gofmt indents the Go sources with tabs, go.mod too; the file names have no spaces
# shellcheck disable=SC2207
tab_files=(Makefile go.mod $(go_sources))

# project_checks: the Go sources
project_checks() {
  section "go"
  check "gofmt formats the sources" "" "$(gofmt -l cmd internal)"
  run_check "go vet" go vet ./...
  run_check "go mod tidy keeps go.mod and go.sum" go mod tidy -diff
}
