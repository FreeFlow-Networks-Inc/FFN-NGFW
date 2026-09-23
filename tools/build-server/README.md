# Linux build workspace

Keep recovered development inputs separate from release sources and artifacts.
`workspace.py` organizes a dedicated server directory without installing imports
into `/usr/local`, changing running services, or rewriting legacy build scripts.
It requires Python 3.10 or later and accepts the deployment root as an argument.

| Directory | Purpose |
| --- | --- |
| `sources/` | Versioned FFN core and hardware-platform repositories |
| `private/imports/vm/clones/` | Preserved VM `/mnt/clones` development trees |
| `private/imports/vm/home-tools/` | Selected VM home-directory tools |
| `private/imports/vm/local-tools/` | VM `/usr/local` tools, not installed globally |
| `private/tools/` | Category links: toolchains, hardware, kernels, networking, images, references, utilities |
| `private/catalog/` | Inventories, transfer verification and compiler checks |
| `work/` | Disposable, separate build working directories |
| `artifacts/` | Unpublished build candidates |
| `published/` | Approved releases only; never serve the workspace root |
| `config/` | Locally supplied build profiles |
| `logs/` | Build and migration logs |

After a resumable copy, compare checksums against the source before marking the
migration verified. Preserve symlinks and hard links but do not follow links into
other filesystems. Exclude credentials, live sockets/device nodes and raw disk
backups; record exclusions in the source inventory. Keep vendor/sysroot data
private. Do not copy a recovered appliance root into a redistributable image.

```sh
python3 tools/build-server/workspace.py --root /srv/ffn-build-server catalog
python3 tools/build-server/workspace.py --root /srv/ffn-build-server doctor
```

`doctor` compiles a temporary freestanding object with each discovered compiler
and validates MIPS64 big-endian output. It records failures as well as working
compilers in `private/catalog/doctor.json`; a successful command alone does not
mean every imported SDK is usable. Select a working compiler explicitly:

```sh
python3 tools/build-server/workspace.py --root /srv/ffn-build-server env \
  --toolchain 'COPY_AN_EXACT_WORKING_ID_FROM_DOCTOR_JSON'
```

The output is shell-quoted `ARCH`, `CROSS_COMPILE`, and `FFN_BUILD_ROOT` exports.
Legacy scripts may still contain old absolute paths or lab network settings.
Preserve them as references and port their inputs to reviewed build profiles;
do not run them blindly on the new host. The platform's
`octeon/images/build_images.py` consumes pinned CP/DP image profiles. The core's
`image/build.sh` requires a clean, explicit preseed for full MP images, and
`opt/ffn_patch.py` creates code-only patch candidates. Imported tools alone are
not a validated full-image or patch release.

## PA-5200 OS policy

Full MP images use Ubuntu amd64. CP and DP candidates use source-built Debian
MIPS64 big-endian, glibc and Linux 6.18+; the OCTEON minimum does not change the
Ubuntu MP kernel. The platform's `octeon/images/os-policy.json` and image input
checks enforce this split. OpenWrt/musl, CentOS, old SDK kernels and mixed
Buildroot initramfs are not eligible inputs. Old OpenWrt/SDK compilers are no
longer discovered by `doctor`.

After an explicitly requested import cleanup, regenerate the catalog. It removes
only stale aliases it previously created, not unrelated symlinks. Keep the
original migration checksum report as historical evidence and record deliberate
cleanup separately; the cleaned copy no longer matches the original snapshot.
Preserve modern board drivers, BCM/FE100 references, SDK hardware interface
headers and Debian package sources separately from retired OS trees.

A successful compiler probe is not a qualified image. Clean packaged runtime
seeds, pinned board patches and native Debian hardware integration still need
CP/DP boot, agent, LACP and policy/NAT validation before release promotion.
