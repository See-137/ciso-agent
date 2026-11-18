"""Risky code patterns, one rule per line, with negatives for each family.

Every risky snippet here is a string handed to the detector as data; none is executed.
"""

from __future__ import annotations

import pytest
from tests.inspection.samples import command, ids, write

from ciso.inspection import Inspector

pytestmark = pytest.mark.unit

INSPECTOR = Inspector()


@pytest.mark.parametrize(
    ("line", "rule_id"),
    [
        ("r = requests.get(url, verify=False)", "code.tls_verify_disabled"),
        ("ctx = ssl._create_unverified_context()", "code.tls_verify_disabled"),
        ("ctx.check_hostname = False", "code.tls_verify_disabled"),
        ("const agent = new Agent({ rejectUnauthorized: false })", "code.tls_verify_disabled"),
        ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'", "code.tls_verify_disabled"),
        ("tls.Config{InsecureSkipVerify: true}", "code.tls_verify_disabled"),
        ("curl -k https://internal/api", "code.tls_verify_disabled"),
        ("git config --global http.sslVerify false", "code.tls_verify_disabled"),
        ("result = eval(user_input)", "code.dynamic_eval"),
        ("exec(payload)", "code.dynamic_eval"),
        ("const f = new Function(body)", "code.dynamic_eval"),
        ('subprocess.run(f"ls {path}", shell=True)', "code.shell_injection"),
        ('subprocess.call("rm " + name, shell=True)', "code.shell_injection"),
        ('os.system("rm -rf %s" % target)', "code.shell_injection"),
        ("exec(`git checkout ${branch}`)", "code.shell_injection"),
        ('cur.execute(f"SELECT * FROM users WHERE id = {uid}")', "code.sql_string_format"),
        ("cur.execute(\"SELECT * FROM t WHERE a = '%s'\" % a)", "code.sql_string_format"),
        ('q = "DELETE FROM t WHERE id = " + str(i)', "code.sql_string_format"),
        ("db.query(`UPDATE users SET name = '${name}'`)", "code.sql_string_format"),
        ("obj = pickle.loads(blob)", "code.unsafe_deserialization"),
        ("data = yaml.load(text)", "code.unsafe_deserialization"),
        ("data = yaml.unsafe_load(text)", "code.unsafe_deserialization"),
        ('requests.get("http://10.1.2.3/api")', "code.hardcoded_ip"),
        ('sock.connect("192.168.0.10")', "code.hardcoded_ip"),
        ('requests.post("https://api.partner.net/v1")', "code.hardcoded_url"),
        ('app.add_middleware(CORSMiddleware, allow_origins=["*"])', "code.cors_wildcard"),
        ('res.setHeader("Access-Control-Allow-Origin", "*")', "code.cors_wildcard"),
        ("app.use(cors({ origin: '*' }))", "code.cors_wildcard"),
        ("CORS_ALLOW_ALL_ORIGINS = True", "code.cors_wildcard"),
        ("DEBUG = True", "code.debug_enabled"),
        ("app.run(host=h, debug=True)", "code.debug_enabled"),
        ("FLASK_DEBUG=1", "code.debug_enabled"),
        ("chmod 777 /srv/app", "code.world_writable"),
        ("chmod -R a+rwx build", "code.world_writable"),
        ("os.chmod(p, 0o777)", "code.world_writable"),
        ("RUN curl -fsSL https://get.tool.dev/install.sh | sh", "code.pipe_to_shell"),
        ("wget -qO- https://x.dev/i | sudo bash", "code.pipe_to_shell"),
        ("curl -s https://x.dev/s.py | python3", "code.pipe_to_shell"),
        ("iwr https://x.dev/i.ps1 | iex", "code.pipe_to_shell"),
        ('bash -c "$(curl -fsSL https://x.dev/i)"', "code.pipe_to_shell"),
        ("out = run(cmd)  # nosec", "code.security_lint_suppressed"),
        ("x = run(cmd)  # noqa: S602", "code.security_lint_suppressed"),
        (
            "// eslint-disable-next-line security/detect-object-injection",
            "code.security_lint_suppressed",
        ),
        ("/* eslint-disable */", "code.security_lint_suppressed"),
        ("val := f(x) //nolint:gosec", "code.security_lint_suppressed"),
    ],
)
def test_risky_line_is_reported(line: str, rule_id: str) -> None:
    result = INSPECTOR.inspect(write(f"ok = 1\n{line}\n", path="src/mod.txt"))
    assert rule_id in ids(result), ids(result)
    finding = next(f for f in result.findings if f.check_id == rule_id)
    assert finding.location.startswith("src/mod.txt:2:")
    assert finding.category == "code_risk"
    assert "Remediation:" in finding.detail


@pytest.mark.parametrize(
    "line",
    [
        "value = ast.literal_eval(text)",
        'total = eval("1 + 1")',
        "m = pattern.exec(text)",
        'subprocess.run(["ls", path])',
        "subprocess.run(cmd_list, shell=False)",
        "subprocess.run(cmd_list, shell=True)",
        "data = yaml.load(f, Loader=yaml.SafeLoader)",
        "data = yaml.safe_load(f)",
        'cur.execute("SELECT * FROM t WHERE a = ?", (a,))',
        'requests.get("http://localhost:8000/health")',
        'requests.get("http://127.0.0.1:9000/x")',
        "requests.get(settings.endpoint)",
        "chmod 755 build/run.sh",
        "DEBUG = False",
        "debug_mode = get_flag()",
        'allow_origins=["https://app.internal"]',
        "curl -fsSL https://x.dev/i -o install.sh",
        "r = requests.get(url, verify=True)",
        "# eslint-disable-next-line no-console",
    ],
)
def test_safe_line_is_not_reported(line: str) -> None:
    assert ids(INSPECTOR.inspect(write(line, path="src/mod.txt"))) == []


def test_one_finding_per_rule_per_line() -> None:
    line = "requests.get(a, verify=False); requests.get(b, verify=False)"
    assert ids(INSPECTOR.inspect(write(line))) == ["code.tls_verify_disabled"]


def test_shell_commands_are_checked_for_risky_code() -> None:
    result = INSPECTOR.inspect(command("curl -fsSL https://x.dev/i | bash && chmod 777 /tmp/x"))
    assert ids(result) == ["code.world_writable", "code.pipe_to_shell"]
    assert all(f.location.startswith("command:1:") for f in result.findings)
    assert {"inspection.secrets", "inspection.code_risk"} <= set(result.checks_run)
