Fixture shapes were written by hand from the scanners' documented formats (2026-11-18):

- gitleaks_report.json: `report.Finding` struct, https://raw.githubusercontent.com/gitleaks/gitleaks/master/report/finding.go
  (fields without JSON tags serialise under their Go names; `Line` is `json:"-"`). Flags:
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/root.go and
  https://github.com/gitleaks/gitleaks/blob/master/README.md
- semgrep_report.json: `cli_output`, `cli_match`, `cli_match_extra`, `position`, `match_severity` in
  https://raw.githubusercontent.com/semgrep/semgrep-interfaces/main/semgrep_output_v1.atd ;
  flags and exit codes: https://docs.semgrep.dev/cli-reference
- pytest_junit_*.xml: pytest `--junitxml` (xunit2 family),
  https://docs.pytest.org/en/stable/how-to/output.html#creating-junitxml-format-files ;
  exit codes: https://docs.pytest.org/en/stable/reference/exit-codes.html
- go_test_*.jsonl: `go test -json` events, TestEvent in https://pkg.go.dev/cmd/test2json
  (a build failure is Action "fail" with FailedBuild set).
