# Ollama dev sandbox

A hardened local Ollama instance for developing/testing the Ollama LLM backend
([issue #52](https://github.com/azva-co/candor/issues/52)) without running an unsandboxed
process directly on your host with your own user's full privileges.

Dev tool only: not part of the release build, not shipped anywhere, no Go package imports it -
same posture as [`hack/grafana-preview/`](../grafana-preview/).

## Run it

**First, make sure your Docker Desktop/Podman Machine VM itself has at least 8GB of memory
allocated** - the default is often 2GB, which is not enough (see the gotchas below for why the
failure isn't an obvious OOM message when this is wrong).

```sh
cd hack/ollama-dev
docker compose up -d   # or: podman compose up -d
```

Pull a model and test it, same as any Ollama install:

```sh
docker compose exec ollama ollama pull llama3.2:3b
curl http://localhost:11434/api/version
```

```sh
docker compose down    # add -v to also drop the model volume
```

## What's actually hardened, and why

| Control | What | Why |
|---|---|---|
| Image | pinned by digest, not a floating tag | same discipline as every other image reference in this repo |
| User | forced `1000:1000` | the image defaults to root - nothing in its own config sets a `USER` |
| Root filesystem | read-only, `tmpfs` for `/tmp` only (`noexec,nosuid`) | a compromised process can't persist anything to the image layer |
| Capabilities | all dropped, none added | serving HTTP and running inference needs zero special capabilities |
| Privilege escalation | blocked (`no-new-privileges`) | closes the setuid-binary escalation path even as non-root |
| Process count | capped at 256 | bounds a runaway fork loop |
| Memory / CPU | capped at 6GB / 4 cores | bounds resource exhaustion from a single model load or a flood of requests - sized generously above a small model's own footprint, see the cgroup gotcha below |
| Network | published to `127.0.0.1` only | not reachable from your LAN - change deliberately, not by accident |
| Model storage | a dedicated named volume | no host directory bind-mounted in |

If you're on Podman rather than Docker Desktop, you also get a real hypervisor boundary underneath
all of the above for free - Podman on macOS runs containers inside its own Linux VM (`applehv`),
not directly on the host, and rootless mode means there's no privileged daemon either.

## Two non-obvious gotchas, hit and fixed while building this

**Wrong home directory silently fails.** The image's `/etc/passwd` maps UID 1000 to `ubuntu`, home
`/home/ubuntu` - not `/root`. Mounting the model volume at `/root/.ollama` while running as
`1000:1000` fails with `mkdir /home/ubuntu/.ollama: read-only file system`, which reads like a
permissions bug but is actually just the wrong path. Check `/etc/passwd` in the image directly
before assuming a path (`docker run --rm --entrypoint cat <image> /etc/passwd`) rather than
guessing - this changed between an earlier version of this image and 0.13.0.

**A container memory limit is a no-op above your VM's own ceiling.** Docker Desktop and Podman
Machine both run containers inside a Linux VM with its own fixed memory allocation, independent of
`mem_limit`/`--memory`. A VM capped at 2GB will still let a 4GB container limit through, then
silently kill the model-loading process once real usage exceeds what the VM actually has - the
error surfaces as `"llama runner process has terminated: signal: killed"`, not an OOM message that
points at the VM. Check your VM's own memory first (`podman machine inspect --format
'{{.Resources.Memory}}'`, or Docker Desktop's Resources settings) before assuming the container
flag is being respected.

**Rootless cgroup v2 counts page cache toward your memory limit, and Ollama's own check is
conservative about it.** Even with a correctly-sized VM and container limit, loading a model can
fail with `"model requires more system memory (2.3 GiB) than is available (2.0 GiB)"` while
`podman stats`/`free -h` both show plenty of memory actually free. The gap: reading a ~2GB model
blob fills the cgroup's page cache, and cgroup v2 counts that cache toward `memory.current` even
though it's reclaimable - `podman exec <container> cat /sys/fs/cgroup/memory.current` will show
this directly, well above what `podman stats` reports (which excludes cache). Ollama's own
memory-availability check reads the stricter cgroup number, not the reclaimable-aware one, so it
sees less headroom than actually exists. Fix: give real headroom above the model's own size, not
just barely enough - this repo's `docker-compose.yml` runs a VM at 8GB with a 6GB container limit
for a 2GB model, not 4GB/4GB, specifically because of this. A model close to its container's memory
ceiling will hit this even though nothing is actually out of memory.

## What this doesn't cover

CPU-only inference - neither Docker Desktop nor Podman Machine passes a GPU through to the Linux VM
on macOS, so expect CPU-speed generation, fine for interactive testing, not a production
performance signal. No model-management automation is provided here on purpose - issue #52
explicitly excludes bundling that; this sandbox is for developing against Ollama, not for how
Candor itself would deploy it (that's its own pod/container, unrelated to the operator's own
ServiceAccount or RBAC).
