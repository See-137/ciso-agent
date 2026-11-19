# Sandbox service (component C5)

Before a push, the governance service sends the change here. The sandbox runs a secret
scanner (gitleaks), a code scanner (semgrep) and the project's own tests, each in its own
isolated container, and returns a report in the fixed format:

```json
{"job_id": "...", "checks": [{"check_id": "secrets|code|tests",
  "status": "passed|failed|error|skipped",
  "findings": [{"rule": "...", "category": "...", "severity": "info|low|medium|high|critical",
                "path": "...", "line": 12, "message": "..."}],
  "tests": {"passed": 0, "failed": 0, "errors": 0}}]}
```

It lives outside `src` because it starts processes (spec section 7: allowed in C5 only).
Nothing in `src` imports it.

## Fail closed

Nothing ever runs on the host. If there is no backend, the container runtime does not
answer, an image is missing, a limit or image is unset, or the archive is hostile, every
affected check comes back `error` with a `sandbox.<reason>` finding. There is no local,
unisolated fallback.

## What the owner (or the company's IT) must provide

Nothing here has run against a real container yet: the build machine's Docker daemon was
not started and no image was pulled by this lane. On 2026-11-19 the owner allowed Docker; the
six base images were pulled on the build machine, but the derived images were not built and
the sandbox was never run in a real container.

1. **A dedicated host** (Linux, x86-64 or arm64) with Docker Engine 20.10 or later, or
   another OCI runtime whose CLI accepts the same `docker run` flags (Podman is likely to,
   but this is not verified). The host should have no credentials or network routes to
   company systems: the containers have no network, but the host is the second wall.
2. **Pinned images, pulled by the owner** (this service runs `--pull never`). Pull each
   once, then record its digest with
   `docker image inspect --format '{{index .RepoDigests 0}}' <image:tag>`:

   | Setting | Must contain | Notes |
   |---|---|---|
   | `gitleaks` | `/bin/sh`, `tar`, `git`, `gitleaks` 8.19 or later (`dir` and `git` subcommands) | the official gitleaks image is Alpine-based and has these; verify |
   | `semgrep` | `/bin/sh`, `tar`, `git`, `semgrep`, and the rules at `semgrep_config` | rules must be baked into the image: registry rules need the network |
   | `git` | `/bin/sh`, `git` | exports the HEAD tree of a bundle for the tests |
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
  `{"job_id", "archive_format": "tar"|"git_bundle", "archive_b64", "base_ref"?, "checks": [...]}`.
  `base_ref` (a full commit id) is for bundles only. Returns 200 with the report; 401 bad
  token; 413 body too large; 422 invalid job; 429 another job is running; 503 token unset.
- `GET /healthz`: 200 when usable, else 503, with `missing` settings and `backend` reasons.

## Known limits

- `npm test` has no structured output: the exit code decides and the counts are zero.
- A git bundle must be complete (cloneable on its own) and have a HEAD.
- Not verified against real tools: `pytest -p no:terminal --junitxml=/dev/stdout` writing
  only XML to stdout; `--log-driver none` with an attached `docker run -i`; busybox `tar`
  reading the GNU-format tar this service builds.
