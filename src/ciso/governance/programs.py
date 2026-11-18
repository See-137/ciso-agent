"""Vocabulary of the command classifier: which programs do what.

Names are the lower-case program name with any directory and any `.exe`, `.com`, `.cmd`
or `.bat` suffix removed (`C:\\Tools\\CURL.EXE` is `curl`). PowerShell aliases are listed
next to their cmdlets. The lists name generic tools; they say what a tool can do, never
whether a use of it is approved: that is the ruleset's job.
"""

from __future__ import annotations

import re

_EXT_RE = re.compile(r"\.(exe|com|cmd|bat)$")
_PIP_RE = re.compile(r"pip[0-9.]*")
_PYTHON_RE = re.compile(r"(python|pypy)[0-9.]*|py")
_VALID_RE = re.compile(r"[a-z0-9_][a-z0-9._+-]*|[\[.%?!{}]|\[\[")


def program_name(text: str) -> str:
    """Normalized program name: basename, lower case, executable suffix removed."""
    base = re.split(r"[\\/]", text)[-1].lower()
    base = _EXT_RE.sub("", base)
    if _PIP_RE.fullmatch(base):
        return "pip"
    if _PYTHON_RE.fullmatch(base):
        return "python"
    return base


_TEXT_RE = re.compile(r"[A-Za-z0-9_.+\-/\\:~ ()\[\]%?!{}]+")


def valid_program_text(text: str) -> bool:
    """The command word as written may hold a path, but no list or expansion syntax."""
    return text.isascii() and bool(_TEXT_RE.fullmatch(text)) and ("," not in text)


def valid_program(name: str) -> bool:
    return bool(name) and name.isascii() and bool(_VALID_RE.fullmatch(name))


def _w(text: str) -> frozenset[str]:
    return frozenset(text.split())


#: Words that only introduce or decorate the real command.
SHELL_KEYWORDS = _w("if then else elif fi for while until do done case esac in ! { } time")

#: Wrappers whose remaining words are the command they run, after their own options.
#: value: options that take a separate argument.
WRAPPERS: dict[str, frozenset[str]] = {
    "nohup": frozenset(),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": _w("-a"),
    "nice": _w("-n"),
    "ionice": _w("-c -n -p"),
    "stdbuf": _w("-i -o -e"),
    "setsid": frozenset(),
    "unbuffer": frozenset(),
    "chrt": frozenset(),
    "taskset": frozenset(),
    "strace": _w("-o -e -p -s"),
    "ltrace": _w("-o -e -p -s"),
    "caffeinate": frozenset(),
    "call": frozenset(),
    "busybox": frozenset(),
    "watch": _w("-n -d"),
    "xargs": _w("-I -i -n -P -d -E -L -s -a"),
    "doas": _w("-u -C"),
    "sudo": _w("-u -g -h -p -C -D -r -t -U -T"),
    "pkexec": _w("--user"),
    "gsudo": _w("-u -d"),
    "chroot": frozenset(),
    "nsenter": _w("-t -m -u -i -n -p -U -S -G"),
    "unshare": frozenset(),
}

#: Running these raises privilege.
PRIVILEGE_WRAPPERS = _w("sudo doas pkexec gsudo su runas")

SHELLS = _w("sh bash zsh dash ksh mksh ash fish csh tcsh yash")
SCRIPT_INTERPRETERS = _w("python perl ruby node nodejs php lua tclsh osascript")
POWERSHELLS = _w("powershell pwsh")
EVALUATORS = _w("eval iex invoke-expression source .")
#: Hosts that run a script or a remote document given as an argument.
SCRIPT_HOSTS = _w("mshta wscript cscript regsvr32 rundll32 msiexec installutil msbuild")

NETWORK = _w(
    "curl wget scp sftp ftp tftp rsync nc ncat netcat socat telnet ssh aria2c lftp http "
    "https xh fetch invoke-webrequest iwr invoke-restmethod irm start-bitstransfer bitsadmin "
    "send-mailmessage smbclient"
)
#: Fragments of a word (case-insensitive) that open a network transfer.
NETWORK_WORD_FRAGMENTS = (
    "net.webclient",
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "uploadstring",
    "uploadfile",
    "uploaddata",
    "net.sockets",
    "net.http.httpclient",
    "/dev/tcp/",
    "/dev/udp/",
)
DECODER_WORD_FRAGMENTS = ("frombase64string",)

#: (program, option) pairs that make a program a decoder.
DECODER_OPTIONS: dict[str, frozenset[str]] = {
    "base64": _w("-d --decode -D"),
    "base32": _w("-d --decode"),
    "basenc": _w("-d --decode"),
    "certutil": _w("-decode -decodehex /decode /decodehex"),
    "xxd": _w("-r -revert"),
    "openssl": _w("-d -base64 -a"),
}
DECODER_ALWAYS = _w("uudecode")

#: Programs that print text (used for the secret-variable check).
PRINTERS = _w("echo printf print write-output write-host write echo.")

#: Print the whole environment when run without a command.
ENV_DUMPERS = _w("env printenv")
ENV_DUMP_WORD_FRAGMENTS = ("getenvironmentvariables",)
SECRET_VARIABLE_RE = re.compile(
    r"(?i).*(token|secret|passw|pwd|api_?key|credential|private_?key|access_?key).*"
)

CREDENTIAL_PROGRAMS = _w("cmdkey vaultcmd")
#: program -> first argument values that read stored credentials.
CREDENTIAL_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "security": _w(
        "find-generic-password find-internet-password find-certificate dump-keychain export"
    ),
    "secret-tool": _w("lookup search"),
    "keyring": _w("get"),
}
CREDENTIAL_WORD_FRAGMENTS = ("lsass", "--export-secret-keys", "--export-secret-subkeys")

DESTRUCTIVE_ALWAYS = _w(
    "shred wipe srm mkfs diskpart format clear-disk format-volume remove-partition cipher"
)
#: Recursive-delete programs (and PowerShell aliases of Remove-Item).
DELETERS = _w("rm del erase rd rmdir ri remove-item")

PACKAGE_ALWAYS = _w(
    "npx bunx uvx pnpx install-module install-package install-script add-appxpackage "
    "install-psresource"
)
#: program -> subcommands that install (empty: the first positional argument decides).
PACKAGE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "pip": _w("install download"),
    "npm": _w("install i in ins isntall add ci update up upgrade exec x"),
    "yarn": _w("add install dlx global up upgrade"),
    "pnpm": _w("add install i dlx update up"),
    "bun": _w("add install i x"),
    "uv": _w("add pip tool sync"),
    "pipx": _w("install run inject upgrade"),
    "cargo": _w("install add"),
    "go": _w("install get"),
    "gem": _w("install update"),
    "apt": _w("install upgrade full-upgrade dist-upgrade reinstall"),
    "apt-get": _w("install upgrade dist-upgrade reinstall"),
    "dnf": _w("install upgrade reinstall"),
    "yum": _w("install upgrade reinstall"),
    "zypper": _w("install in update up"),
    "apk": _w("add upgrade"),
    "brew": _w("install reinstall upgrade tap"),
    "choco": _w("install upgrade"),
    "winget": _w("install upgrade"),
    "scoop": _w("install update"),
    "conda": _w("install create update"),
    "mamba": _w("install create update"),
    "micromamba": _w("install create update"),
    "poetry": _w("add install update"),
    "pdm": _w("add install update"),
    "composer": _w("require install update"),
    "dotnet": _w("add tool"),
    "snap": _w("install refresh"),
    "flatpak": _w("install update"),
    "nuget": _w("install"),
}
#: program -> options that install.
PACKAGE_OPTIONS: dict[str, frozenset[str]] = {
    "dpkg": _w("-i --install"),
    "rpm": _w("-i -U --install --upgrade -ivh -Uvh"),
    "msiexec": _w("/i /package -i -package"),
    "pacman": _w("-S -Sy -Syu -U"),
}
#: `yarn` with no subcommand installs.
INSTALL_WITHOUT_ARGS = _w("yarn")

CONTAINER_VM = _w(
    "docker podman nerdctl buildah ctr crictl kubectl helm minikube kind k3d k3s vagrant "
    "virsh virt-install qemu-img vboxmanage virtualbox multipass lxc lxd incus colima "
    "limactl wsl nsenter unshare chroot systemd-nspawn firecracker docker-compose "
    "podman-compose new-vm start-vm stop-vm remove-vm set-vm checkpoint-vm hyper-v"
)
CONTAINER_VM_PREFIXES = ("qemu-system-",)

PRIVILEGE = _w("su runas setcap visudo takeown add-localgroupmember new-localuser")
PRIVILEGE_GROUPS = _w("sudo wheel admin root administrators")

#: Substrings of a service or unit name that make it a security control.
SECURITY_SERVICE_FRAGMENTS = (
    "defend",
    "firewall",
    "mpssvc",
    "audit",
    "syslog",
    "eventlog",
    "sysmon",
    "osquery",
    "apparmor",
    "selinux",
    "ufw",
    "iptables",
    "nftables",
    "antivir",
    "antimalware",
    "security",
    "edr",
    "xdr",
)
TAMPER_ALWAYS = _w(
    "clear-eventlog remove-eventlog limit-eventlog setenforce fltmc csrutil spctl clear-history"
)
SERVICE_CONTROLLERS = _w(
    "sc systemctl service launchctl stop-service set-service remove-service suspend-service net"
)
SERVICE_STOP_VERBS = _w(
    "stop disable mask delete config unload remove bootout kill stop-service "
    "set-service remove-service suspend-service"
)
