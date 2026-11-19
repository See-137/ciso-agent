"""Review-round fixes in inspection: M4 (secret misses), L2 (missing sensitive paths),
the inspection side of M1 and Q3 (path aliases, globs, variables, shell write targets).

Secrets and sensitive targets are assembled from fragments at run time (`samples.j`), so
this file never holds a token-shaped literal or a complete line that plants a key.
"""

from __future__ import annotations

import pytest
from tests.inspection.samples import ASSIGNED, CLOUD_KEY, SERVICE_TOKEN, command, ids, j, write

from ciso.inspection import Inspector, sensitive_path_rules

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()


def _rules(path: str) -> set[str]:
    return {rule.rule_id for rule in sensitive_path_rules(path)}


# -- M4: secrets the scanner missed -----------------------------------------------------

#: (file path, content) pairs the review measured as clean; each must now be a finding.
MISSES: tuple[tuple[str, str], ...] = (
    ("app.env", j("DB_", "PASS=", ASSIGNED)),
    ("app.env", j("SIGNING", "_KEY=", ASSIGNED)),
    ("app.env", j("db", "Password: ", ASSIGNED)),
    ("app.ini", j("Db-", "Pwd = ", ASSIGNED)),
    ("app.yaml", j("password", ' = "my-', ASSIGNED, '"')),
    ("app.yaml", j("password", ": env-", ASSIGNED)),
    ("app.sh", j("password", "=$", "ecr3t", "Pa55word")),
    ("app.py", j("PASS", "WORD = ", "Xk2!9", "dkQ7zz")),
    ("app.yaml", j("db:\n  password", ": |\n    ", ASSIGNED, "\n  host: db\n")),
    ("app.yaml", j("password", ": >-\n\n  ", ASSIGNED, "\n")),
    ("notes.txt", j("key id ", CLOUD_KEY.lower())),
    ("app.js", j("const t = '", SERVICE_TOKEN[:14], "' + '", SERVICE_TOKEN[14:], "';")),
    ("app.py", j('token = ("', ASSIGNED[:3], '" "', ASSIGNED[3:], '")')),
)


@pytest.mark.parametrize(("path", "content"), MISSES, ids=[f"miss{i}" for i in range(len(MISSES))])
def test_m4_reviewer_misses_are_found(path: str, content: str) -> None:
    result = INSPECTOR.inspect(write(content, path=path))
    found = [f for f in result.findings if f.category == "secret"]
    assert found, content.split("=")[0]
    assert result.complete is True
    for finding in result.findings:
        assert ASSIGNED not in finding.detail + finding.location


#: Ordinary lines that must stay clean (precision): names that merely contain a word,
#: references, placeholders, types, paths, block scalars of non-secrets.
BENIGN: tuple[tuple[str, str], ...] = (
    ("app.yaml", "sort_key: name"),
    ("app.py", 'cache_key = "users"'),
    ("app.yaml", "primary_key: id_column"),
    ("app.py", 'key = "value"'),
    ("app.yaml", "keyboard_layout: en-US-intl"),
    ("app.yaml", "max_tokens: 4096"),
    ("app.yaml", "token_type: bearer"),
    ("app.ini", "password_min_length = 12"),
    ("app.env", "PWD=/home/dev/project"),
    ("app.yaml", "password_file: /run/config/db_pass"),
    ("app.yaml", "password: ${DB_PASSWORD}"),
    ("app.yaml", 'password: "$DB_PASSWORD"'),
    ("app.sh", "PASSWORD=$db_password"),
    ("app.yaml", "password: env.DB_PASSWORD"),
    ("app.js", "const dbPassword = process.env.DB_PASSWORD;"),
    ("app.ps1", "$pwd = $env:DB_PASSWORD"),
    ("app.yaml", "password: 'your-password-here'"),
    ("app.yaml", "password: my-password"),
    ("app.py", 'token = response.json()["token"]'),
    ("app.py", "def check(password: str) -> bool:"),
    ("app.py", "password = getpass.getpass()"),
    ("app.py", "password = default_password"),
    ("app.py", "    pass"),
    ("app.json", '"pass": true,'),
    ("app.py", "access_key = None"),
    ("app.yaml", "password: '********'"),
    ("app.yaml", "token: {{ .Values.token }}"),
    ("app.py", 'version = "1.2.3" + "-beta"'),
    ("app.py", 'url = "https://example.com/" + "path"'),
    ("app.yaml", "signing_key_id: a1b2c3d4e5"),
    ("app.yaml", "encryption_key_path: /etc/keys/app.key"),
    ("app.yaml", "bypass: enabled-always"),
    ("app.yaml", "description: |\n  A long text about the password policy.\n"),
    ("app.yaml", "password: |\n  {{ lookup('env', 'DB_PASSWORD') }}\n"),
    ("app.yaml", "api_key: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n"),
    ("app.sh", 'export GH_TOKEN="$(gh auth token)"'),
    ("app.py", "secret_name = 'payments'"),
    ("notes.txt", "the akia prefix marks a key id"),
    ("notes.txt", "region asiapacificregionhub"),
    ("app.py", 'parts = "abc" "def"'),
)


@pytest.mark.parametrize(
    ("path", "content"), BENIGN, ids=[f"benign{i}" for i in range(len(BENIGN))]
)
def test_m4_precision_benign_lines_stay_clean(path: str, content: str) -> None:
    result = INSPECTOR.inspect(write(content, path=path))
    assert [f for f in result.findings if f.category == "secret"] == []
    assert "inspection.secrets" in result.checks_run


def test_complete_means_every_check_ran_not_that_no_secret_exists() -> None:
    # A value split across two lines is not a finding, yet the result is complete:
    # `complete` says the checks ran, never that the content is free of secrets.
    content = j('a = "', SERVICE_TOKEN[:14], '"\nb = "', SERVICE_TOKEN[14:], '"\n')
    result = INSPECTOR.inspect(write(content, path="x.txt"))
    assert result.complete is True


# -- L2: paths that were missing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        (j("~/.ss", "h/authorized_keys"), "path.ssh_access"),
        (j("/home/u/.ss", "h/authorized_keys2"), "path.ssh_access"),
        (j("~/.ss", "h/config"), "path.ssh_access"),
        (".vscode/tasks.json", "path.editor_autorun"),
        (".vscode/settings.json", "path.editor_autorun"),
        (".vscode/launch.json", "path.editor_autorun"),
        (".idea/runConfigurations/app.xml", "path.editor_autorun"),
        (".idea/workspace.xml", "path.editor_autorun"),
        (".cursor/rules/style.mdc", "path.assistant_config"),
        (".cursor/mcp.json", "path.assistant_config"),
        (".cursorrules", "path.assistant_config"),
        (".windsurf/rules/x.md", "path.assistant_config"),
        (".windsurfrules", "path.assistant_config"),
        (".github/copilot-instructions.md", "path.assistant_config"),
        ("AGENTS.md", "path.assistant_config"),
        ("pkg/agents.md", "path.assistant_config"),
    ],
)
def test_l2_missing_sensitive_paths_are_reported(path: str, rule_id: str) -> None:
    assert rule_id in _rules(path)
    assert rule_id in ids(INSPECTOR.inspect(write("x", path=path)))


@pytest.mark.parametrize(
    "path", [".vscode/extensions.json", ".github/README.md", "docs/agents.mdx", ".ssh/known"]
)
def test_l2_neighbours_stay_clean(path: str) -> None:
    assert _rules(path) == set()


# -- M1 (inspection side): aliases, 8.3 names, globs, variables -------------------------


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        (".mcp.json.", "path.assistant_config"),
        (".mcp.json::$DATA", "path.assistant_config"),
        ("proj/.claude/settings.json ", "path.assistant_config"),
        ("C:/Users/u/CLAUDE~1/settings.json", "path.assistant_config"),
        (r"C:\Users\u\CLAUDE~1\SETTIN~1.JSO", "path.assistant_config"),
        ("MCP~1.JSO", "path.assistant_config"),
        (j("~/SSH~1/id_r", "sa"), "path.private_key_file"),
        (".mc[p].json", "path.assistant_config"),
        (j("~/.ss?/id_", "*"), "path.private_key_file"),
        (j("~/.ss[h]/id_rs[a]"), "path.private_key_file"),
        (".en[v]", "path.env_file"),
        (".clau*/settings.json", "path.assistant_config"),
        ("$CFG/settings.json", "path.assistant_config"),
        ("${HOOKS}/pre-commit", "path.git_hook"),
        ("%APPDATA%/../.claude/settings.json", "path.assistant_config"),
        ("$env:USERPROFILE/.aws/credentials", "path.cloud_credentials"),
        (".github/$W/ci.yml", "path.ci_pipeline"),
    ],
)
def test_m1_aliases_globs_and_variables_match(path: str, rule_id: str) -> None:
    assert rule_id in _rules(path)


@pytest.mark.parametrize(
    "path",
    [
        "pages/[id].tsx",
        "src/*.py",
        "PROGRA~1/app/readme.txt",
        "build/out~1.txt",
        "logs/$DATE.txt",
        "src/components/[slug]/page.tsx",
        "tests/test_*.py",
    ],
)
def test_m1_ordinary_globs_and_short_names_stay_clean(path: str) -> None:
    assert _rules(path) == set()


def test_m1_a_whole_segment_variable_may_be_any_directory() -> None:
    # `$VERSION` could hold `.claude`: an unknown directory is not cleared.
    assert "path.assistant_config" in _rules("docs/$VERSION/notes.md")


def test_m1_too_many_unknowns_match_every_rule() -> None:
    from ciso.inspection.paths import PATH_RULES

    assert set(sensitive_path_rules("$A/$B/$C/x")) == set(PATH_RULES)


def test_m1_every_sensitive_name_is_reported_somewhere() -> None:
    from ciso.inspection.path_wild import SENSITIVE_CHAINS, SENSITIVE_NAMES

    parents = ("", ".claude/", ".github/", ".github/workflows/", ".git/", ".git/hooks/",
               ".aws/", ".config/gcloud/", ".kube/", ".docker/", ".ssh/", ".vscode/",
               ".idea/", ".idea/runconfigurations/", ".gitlab/", ".gitlab/ci/", ".gem/",
               ".cargo/", ".nuget/", ".azure/")  # fmt: skip
    for name in SENSITIVE_NAMES + SENSITIVE_CHAINS:
        tails = ("", "/x")
        assert any(_rules(parent + name + tail) for parent in parents for tail in tails), name


# -- Q3: shell write targets ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "rule_id"),
    [
        (j("echo x >", " .mcp.json."), "path.assistant_config"),
        (j("echo x >> ", "~/CLAUDE~1/settings.json"), "path.assistant_config"),
        (j("cd .claude && echo x", " > settings.json"), "path.assistant_config"),
        (j("cp x ", ".mc[p].json"), "path.assistant_config"),
        (j("printf k | tee -a ", "~/.ss", "h/authorized_keys"), "path.ssh_access"),
        (j("Set-Content -Path ", ".vscode/tasks.json", " -Value x"), "path.editor_autorun"),
        (j("echo x | Out-File ", ".git/hooks/pre-push"), "path.git_hook"),
        (j("Copy-Item a -Destination ", "'.github/workflows/ci.yml'"), "path.ci_pipeline"),
        (j("echo x 2>", '"AGENTS.md"'), "path.assistant_config"),
        (j("mv a.txt ", ".env"), "path.env_file"),
    ],
)
def test_q3_shell_write_targets_are_path_findings(text: str, rule_id: str) -> None:
    result = INSPECTOR.inspect(command(text))
    assert rule_id in ids(result)
    assert "inspection.paths" in result.checks_run


@pytest.mark.parametrize(
    "text",
    [
        "cat .mcp.json",
        "echo hi > out.txt",
        "ls 2>&1 > log.txt",
        "cp .env.example config/app.ini",
        "grep -r token src > /dev/null",
        "git diff > changes.patch",
    ],
)
def test_q3_reads_and_ordinary_targets_stay_clean(text: str) -> None:
    result = INSPECTOR.inspect(command(text))
    assert [f for f in result.findings if f.category == "sensitive_path"] == []
