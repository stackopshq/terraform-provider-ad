# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Terraform provider for Windows Active Directory. It manages AD objects (users, groups, OUs, computers, GPOs, group policy links, GPO security settings, GPO registry values and object delegations/ACEs) by running PowerShell commands on a Windows Server over WinRM. The provider does **not** speak LDAP — every operation is ultimately a PowerShell `*-AD*` cmdlet executed remotely (or locally when Terraform itself runs on the Windows host).

This is a Terraform Plugin SDK v2 provider (not the newer Plugin Framework), still labeled a HashiCorp tech preview.

## Common commands

```sh
make build              # gofmt check + go install
make test               # unit tests (fmtcheck first), 30s timeout, parallel=4
make testacc            # acceptance tests — REQUIRES a live AD/WinRM target (TF_ACC=1, 120m timeout)
make testrace           # unit tests with the race detector
make lint               # golangci-lint
make tflint             # tfproviderlintx (Terraform provider-specific linters) + terrafmt on acc tests
make fmt / make fumpt   # gofmt -s / gofumpt -s over all non-vendor .go files
make depscheck          # verifies go mod tidy + go mod vendor produce no diff
make tools              # install all lint/doc tooling (misspell, tfproviderlint, tfproviderdocs, terrafmt, gofumpt, golangci-lint)
```

Dependencies are vendored (`GOFLAGS=-mod=vendor` is exported by the Makefile). After changing `go.mod`, run `go mod tidy && go mod vendor` or `make depscheck` will fail in CI.

### Running a single test

```sh
go test ./ad/internal/gposec/ -run TestPasswordPolicies -v          # one unit test
make testacc TESTARGS='-run TestAccUser_basic'                       # one acceptance test
```

Most files under `ad/` are acceptance tests (`TF_ACC=1`) that need a real domain controller and the `TF_VAR_ad_*` environment variables — copy `devrc.example`, fill it in, and `source` it. The genuinely runnable-without-AD unit tests live under `ad/internal/gposec/` and `ad/internal/winrmhelper/winrm_helper_test.go`.

## Architecture

Three layers, top to bottom:

1. **`ad/` (provider + resources/data sources)** — `provider.go` declares the schema, the `ResourcesMap`/`DataSourcesMap`, and `ConfigureFunc`. Each `resource_ad_*.go` / `data_source_ad_*.go` defines a Terraform schema and CRUD callbacks. CRUD functions are thin: they read `*schema.ResourceData`, marshal it into a struct, and delegate to `winrmhelper`. `meta interface{}` is always a `*config.ProviderConf`.

2. **`ad/internal/config`** — connection setup and the runtime config object. `ProviderConf` holds a `Settings` struct plus **pools of WinRM clients** guarded by a mutex. Always use `AcquireWinRMClient()` / `ReleaseWinRMClient()` (and the `WinRMCP` equivalents for SYSVOL file uploads) — `defer` the release. Three behavioral flags drive command construction across the codebase:
   - `IsConnectionTypeLocal()` — true only on Windows with no WinRM host/creds; runs PowerShell via `exec` instead of WinRM.
   - `IsPassCredentialsEnabled()` — requires HTTPS; wraps commands in a `PSCredential`.
   - `IdentifyDomainController()` — returns the specific DC or falls back to the domain name; passed as the `-Server` argument.

   This package also implements Kerberos auth (`KerberosTransporter`) as a custom WinRM transport using `gokrb5`/`spnego`, supporting password and keytab auth.

3. **`ad/internal/winrmhelper`** — the PowerShell execution layer. One `winrm_<object>.go` file per AD object type, each defining a Go struct mirroring the AD object (JSON-tagged to match PowerShell `ConvertTo-Json` output) and `New…FromResource` / `Get…FromHost` / `addCmd` / `modifyCmd` / `delete` helpers.

### How a PowerShell command is built and run

`powershell_command.go` is central. `NewPSCommand(cmds []string, opts CreatePSCommandOpts)` assembles the final command string, conditionally wrapping it in `Invoke-Command -ScriptBlock`, prepending `$Credential` setup, appending `-Server`/`-Computername`, and adding `| ConvertTo-Json`. `(*PSCommand).Run(conf)` acquires a pooled client, runs the command (remote or local), and returns a `PSCommandResult{Stdout, StdErr, ExitCode}`. Always check **both** `err` and `result.ExitCode != 0`. PowerShell error output comes back as CLIXML and is decoded into a readable message by `decodeXMLCli`.

### Command injection safety

All user-supplied strings interpolated into PowerShell **must** pass through `SanitiseString` / `SanitiseTFInput` (`winrm_helper.go`), which escapes PowerShell metacharacters (backtick, `$`, quotes, control chars). Follow this pattern when adding any new field that reaches a command.

### GPO security settings (`ad/internal/gposec` + `ad/internal/adschema`)

`ad_gpo_security` is the most complex resource. It does not call cmdlets per setting; instead it serializes the whole Terraform schema into a Windows security `GptTmpl.inf` (INI/INF format) and **uploads it to SYSVOL** via the WinRMCP client. `adschema/resource_ad_gpo_security_schema_helper.go` defines the large nested schema; `gposec/` maps each INF section (`password_policies`, `kerberos_settings`, `event_audit`, `restricted_groups`, `registry_values`, etc.) to a Go struct with both `ini:` and `mapstructure:` tags. `inihelper.go` does the bidirectional conversion (resource data ⇄ INF). Each section has a unit test — these are the best examples to read and the safest tests to run locally.

## Docs & examples

- `docs/` is generated; edit `templates/` (only `index.md.tmpl` is overridden) and the `examples/` HCL, then regenerate — do not hand-edit `docs/`.
- `examples/resources/<name>/` and `examples/data-sources/<name>/` hold the canonical HCL surfaced in docs and validated by `scripts/validate-examples.sh`.
- Update `CHANGELOG.md` for user-facing changes (uses `[GH-####]` PR reference links).

## Conventions

- Go is pinned via `.go-version`; `go.mod` declares `go 1.23`.
- Schema fields are snake_case; string fields whose AD value is case-insensitive (DNs, containers) use `DiffSuppressFunc: suppressCaseDiff`.
- Resources support import via `schema.ImportStatePassthroughContext` (the import ID is the object GUID).
- Provider config is read from `winrm_*` / `krb_*` schema args, each with an `AD_*` env-var `DefaultFunc` fallback.
