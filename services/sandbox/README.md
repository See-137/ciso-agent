# Sandbox service (component C5)

Before a push, the governance service sends the change here. The sandbox runs a secret
scanner (gitleaks), a code scanner (semgrep) and the project's own tests, each in its own
isolated container, and returns a report in the fixed format:

```json
{"job_id": "...", "head": "<commit>|null", "checks": [{"check_id": "secrets|code|tests",
  "status": "passed|failed|error|skipped",
  "findings": [{"rule": "...", "category": "...", "severity": "info|low|medium|high|critical",
                "path": "...", "line": 12, "message": "..."}],
  "tests": {"passed": 0, "failed": 0, "errors": 0}}]}
```

`head` is the commit a bundle job's HEAD was verified to be (see below); `null` for a tar
job and whenever the bundle did not match the job.

It lives outside `src` because it starts processes (spec section 7: allowed in C5 only).
Nothing in `src` imports it.

## A bundle is checked before it is scanned (review M2, H1)

A bundle job states `head` (the commit its HEAD must be) and `commits` (every commit of
the range, head first, at most 1000), and optionally `base_ref` (the range starts above
it; none: the whole history). Before any scanner or test runs, a container from the `git`
image clones the bundle and checks that HEAD is `head`, that `base_ref` is an ancestor of
HEAD inside the bundle, and that `git rev-list base_ref..HEAD` (or `git rev-list HEAD`)
is exactly the set of `commits` (`verify.py`). Any difference, or a git failure, ends the
job: every check is `error` with `sandbox.range_mismatch`, nothing else runs, and `head`
is `null`. Every later bundle container checks again that its own clone's HEAD is the
verified head (`SANDBOX_HEAD`) before it runs.

## The scanned code cannot configure the scanners (review H3)

- gitleaks always gets `--config <gitleaks_config>` (a file in the image; with no
  `--config`, gitleaks would load the target's own `.gitleaks.toml`),
  `--gitleaks-ignore-path <gitleaks_ignore_file>` (an EMPTY file in the image, so the
  repository's `.gitleaksignore` is never read) and `--ignore-gitleaks-allow` (inline
  `gitleaks:allow` comments are not honoured). Flags from the gitleaks README,
  https://github.com/gitleaks/gitleaks, fetched 2026-11-19.
- A bundle is scanned twice by gitleaks: the history (`git` mode, `base_ref..HEAD` or
  everything) and the checked-out tree (`dir` mode). The two runs are one `secrets` check
  (the worse status, findings of both).
- semgrep runs with `--disable-nosem` (no `nosemgrep` comments) and
  `--x-ignore-semgrepignore-files` (no `.semgrepignore`). The semgrep CLI reference
  (https://docs.semgrep.dev/cli-reference, fetched 2026-11-19) marks the second flag
  "[INTERNAL]", so it may change between semgrep releases: pin the image and re-check.
  Nested `.semgrepignore` files rely on that flag alone.
- The fixed scripts move `.gitleaks.toml`, `.gitleaksignore` and `.semgrepignore` at the
  scanned root to `/work/tmp` before anything runs (tracked ones are marked skip-worktree
  first, so semgrep's baseline sees a clean tree), and the bundle script writes
  `* diff -export-ignore -export-subst` to `.git/info/attributes`. That file outranks
  every `.gitattributes` in the tree, so `git log -p` shows every file as text (a
  committed `-diff` cannot hide a file from the history scan) and `git archive` exports
  every file as committed for the tests.
- The containers' environment is fixed (`HOME`, `TMPDIR`, `LANG`, per-tool values and
  `SANDBOX_HEAD`); no `GITLEAKS_*` or `SEMGREP_*` variable is ever set.

None of this has run against the real scanner binaries here (no Docker on the build
machine); it is from the vendors' documentation.

## Fail closed

Nothing ever runs on the host. If there is no backend, the container runtime does not
answer, an image is missing, a limit or image is unset, or the archive is hostile, every
affected check comes back `error` with a `sandbox.<reason>` finding. There is no local,
unisolated fallback.

## What the owner (or the company's IT) must provide

Nothing here has run against a real container yet: the build machine's Docker daemon was
not started and no image was pulled (that needs the owner's permission).

1. **A dedicated host** (Linux, x86-64 or arm64) with Docker Engine 20.10 or later, or
   another OCI runtime whose CLI accepts the same `docker run` flags (Podman is likely to,
   but this is not verified). The host should have no credentials or network routes to
   company systems: the containers have no network, but the host is the second wall.
2. **Pinned images, pulled by the owner** (this service runs `--pull never`). Pull each
   once, then record its digest with
   `docker image inspect --format '{{index .RepoDigests 0}}' <image:tag>`:

   | Setting | Must contain | Notes |
   |---|---|---|
   | `gitleaks` | `/bin/sh`, `tar`, `git`, `gitleaks` 8.19 or later (`dir` and `git` subcommands, `--ignore-gitleaks-allow`), the rules at `gitleaks_config` and an EMPTY file at `gitleaks_ignore_file` | both files must be baked into the image; the official image is Alpine-based; verify |
   | `semgrep` | `/bin/sh`, `tar`, `git`, `semgrep`, and the rules at `semgrep_config` | rules must be baked into the image: registry rules need the network |
   | `git` | `/bin/sh`, `git` | verifies every bundle's head and range, and exports the HEAD tree for the tests; required for bundle jobs |
   | `python_tests` | `/bin/sh`, `tar`, `python` with `pytest` | the project's dependencies must already be installed: there is no network to install them |
   | `node_tests` | `/bin/sh`, `tar`, `node`, `npm` | same: `node_modules` cannot be fetched |
   | `go_tests` | `/bin/sh`, `tar`, `go` | same: `GOPROXY=off`, modules must be vendored or in the image |

   Every image must work as user `65534:65534` with a read-only root and `HOME=/work`.
3. **Limits** (no defaults; unset means every job is refused): `wall_time_seconds` per job,
   and per container `cpus`, `memory_bytes` (at least 6 MiB), `output_bytes` (stdout cap),
   `pids`, `work_tmpfs_bytes` (size of the only writable directory).
4. **A token** of at least 16 characters, in the environment variable named by
   `token_env`. Never in the file.

Copy `settings.example.json`, fill it in, then start the service (Git Bash, repo root):

```bash
export CISO_SANDBOX_TOKEN=...            # the governance service uses the same value
uv run python -m services.sandbox.serve /path/to/sandbox-settings.json
curl -s http://127.0.0.1:8790/healthz    # {"usable": true, "missing": [], "backend": []}
```

and run the real-container test, which plants a fake AWS key and a failing test, and
checks from inside the container that it is non-root, has no network, has a read-only
root and sees none of the host's environment (Git Bash, repo root, on the sandbox host):

```bash
export CISO_SANDBOX_CONFIG=/path/to/sandbox-settings.json
uv run pytest tests/services/sandbox/test_real_container.py -rs
```

Without `CISO_SANDBOX_CONFIG`, or when `/healthz` would say not usable, that test is
skipped with the reason.

## The container invocation

Built in `docker.py` (`build_run_argv`), one flag per isolation property, each with its
own test in `tests/services/sandbox/test_docker_invocation.py`:

```
<docker_cli> run --rm -i --name sbx_<id> --pull never
  --network none --read-only
  --tmpfs /work:rw,exec,nosuid,nodev,size=<work_tmpfs_bytes>,mode=1777
  --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges
  --pids-limit <pids> --cpus <cpus> --memory <memory_bytes>b --memory-swap <memory_bytes>b
  --ipc none --log-driver none --workdir /work --entrypoint /bin/sh
  --env HOME=/work --env TMPDIR=/work/tmp --env LANG=C.UTF-8 [fixed per-tool env]
  <image>@sha256:<digest> -c <fixed script> sandbox <command words...>
```

The code is streamed on stdin into the tmpfs (no host mount of any kind). For a tar job
the sandbox streams a tar it rebuilt after validation (`archive.py`), not the original.
The command words are positional arguments to a fixed script (`"$@"`), so job data is
never interpolated into a shell. On timeout or output overflow the container is
`docker kill`ed and `docker rm -f`ed.

## API

- `POST /v1/jobs`, `Authorization: Bearer <token>`, body
  `{"job_id", "archive_format": "tar"|"git_bundle", "archive_b64", "base_ref"?, "head"?, "commits"?, "checks": [...]}`.
  `base_ref`, `head` and `commits` (full commit ids) are for bundles only; `head` and
  `commits` (1-1000, distinct, head first) are required for a bundle. Returns 200 with the report; 401 bad
  token; 413 body too large; 422 invalid job; 429 another job is running; 503 token unset.
- `GET /healthz`: 200 when usable, else 503, with `missing` settings and `backend` reasons.

## Known limits

- `npm test` has no structured output: the exit code decides and the counts are zero.
- A git bundle must be complete (cloneable on its own) and have a HEAD.
- Not verified against real tools: `pytest -p no:terminal --junitxml=/dev/stdout` writing
  only XML to stdout; `--log-driver none` with an attached `docker run -i`; busybox `tar`
  reading the GNU-format tar this service builds.
