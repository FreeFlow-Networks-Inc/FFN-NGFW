#!/usr/bin/env bash
# ffn-pipeline.sh -- model-targeted FFN image pipeline.
#
#   ./ffn-pipeline.sh --model pa-5220
#   ./ffn-pipeline.sh --model pa-5220 --stage preflight
#   ./ffn-pipeline.sh --model pa-5220 --stage verify --artifact out/xxx-rootfs.tar.zst
#
# Four gated stages:
#
#   preflight  cheap checks that must hold BEFORE a long build: signing keys,
#              a root password, WebUI parses, selftests, tools, disk space.
#              Everything here has previously cost a full build cycle to find
#              out the hard way.
#   build      runs build.sh with the model profile applied.
#   verify     runs verify-image.sh against the produced rootfs. A failure here
#              means the artifact is NOT published.
#   publish    signs the rootfs with ed25519 and publishes it as an `image`
#              payload, so appliances can pull it via the A/B updater.
#
# The pipeline refuses to publish an image it could not verify. That ordering is
# the point: an unverified image reaching the update server is how every
# appliance gets a broken build at once.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MODEL=""; STAGE="all"; ARTIFACT=""; UPDATES_DIR="/srv/ffn-updates"; YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --model)    MODEL="$2"; shift 2 ;;
    --stage)    STAGE="$2"; shift 2 ;;
    --artifact) ARTIFACT="$2"; shift 2 ;;
    --updates)  UPDATES_DIR="$2"; shift 2 ;;
    --yes|-y)   YES=1; shift ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
[ -n "$MODEL" ] || { echo "usage: $0 --model <name> [--stage preflight|build|verify|publish|all]"; exit 2; }

PROFILE="$HERE/profiles/${MODEL}.conf"
[ -f "$PROFILE" ] || { echo "no profile: $PROFILE"; echo "available:"; ls "$HERE/profiles" 2>/dev/null | sed 's/^/  /'; exit 2; }

export FFN_PROFILE="$PROFILE"
# Source config.sh, not the profile directly: config.sh lays down the generic
# defaults and then re-sources $FFN_PROFILE at its end, so the model's values win
# and we get BUILD_ROOT/OUT/FFN_ROOT_PW as well.
# shellcheck disable=SC1090,SC1091
set -a; . "$HERE/config.sh"; set +a
[ "${FFN_MODEL:-}" = "$MODEL" ] || die "profile did not apply (FFN_MODEL='${FFN_MODEL:-}', expected '$MODEL')"

banner(){ printf '\n\033[1;35m===== %s =====\033[0m\n' "$*"; }
die(){ printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

PF_FAIL=0
pfok(){  printf '  \033[32mok  \033[0m %s\n' "$*"; }
pfbad(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; PF_FAIL=$((PF_FAIL+1)); }
pfwarn(){ printf '  \033[33mwarn\033[0m %s\n' "$*"; }

# =============================================================== preflight ====
preflight(){
  banner "preflight — ${MODEL}"

  # Credentials. An image with no root password is unloginnable on a headless
  # box, and that is only discoverable after flashing it.
  if [ -n "${FFN_ROOT_PW:-}" ]; then pfok "FFN_ROOT_PW is set"
  elif [ -n "${FFN_SSH_PUBKEY:-}" ]; then
    pfwarn "no FFN_ROOT_PW, but FFN_SSH_PUBKEY is set (no console login)"
  else
    pfbad "neither FFN_ROOT_PW nor FFN_SSH_PUBKEY set — the image would be unloginnable"
  fi

  # Signing. Publishing needs the private seed; the image needs only the public.
  if [ -s /etc/ffn-ngfw/update-sign.key ]; then pfok "ed25519 signing seed present"
  else pfbad "no /etc/ffn-ngfw/update-sign.key — run: ffn_ed25519.py --keygen /etc/ffn-ngfw/update-sign"; fi
  if [ -s /etc/ffn-ngfw/update-sign.pub ]; then
    pfok "public key $(cut -c1-16 < /etc/ffn-ngfw/update-sign.pub)... will ship in the image"
  else pfbad "no /etc/ffn-ngfw/update-sign.pub to stage"; fi

  # Source health.
  local SRC=/opt/ffn-ngfw-v2
  [ -d "$SRC" ] || pfbad "$SRC missing — nothing to package"
  if python3 -m py_compile "$SRC/ffn_manager.py" 2>/dev/null; then pfok "ffn_manager.py compiles"
  else pfbad "ffn_manager.py does NOT compile"; fi

  if [ -x "$SRC/ffn_jscheck.py" ]; then
    if python3 "$SRC/ffn_jscheck.py" "$SRC/static/index.html" >/tmp/pf-js.out 2>&1; then
      pfok "WebUI JavaScript parses"
    else
      pfbad "WebUI JavaScript has structural errors:"; sed 's/^/        /' /tmp/pf-js.out | head -5
    fi
  else pfwarn "ffn_jscheck.py absent — WebUI not parsed"; fi

  for t in ffn_ed25519 ffn_payload ffn_jscheck; do
    if [ -f "$SRC/$t.py" ]; then
      if python3 "$SRC/$t.py" ${t:+selftest} >/tmp/pf-$t.out 2>&1 \
         || python3 "$SRC/$t.py" --selftest >/tmp/pf-$t.out 2>&1; then
        pfok "$t selftest: $(grep -o '[0-9]* failed' /tmp/pf-$t.out | tail -1)"
      else
        pfbad "$t selftest FAILED"; grep FAIL /tmp/pf-$t.out | head -3 | sed 's/^/        /'
      fi
    else pfwarn "$t.py absent"; fi
  done

  # Model dataplane sources.
  if [ -n "${FFN_DP_PORTS:-}" ]; then
    if [ -f "$SRC/octeon-dp/Makefile" ]; then pfok "dataplane sources present (ports: $FFN_DP_PORTS)"
    else pfbad "octeon-dp sources missing — image would have no forwarder"; fi
  fi

  # Host tooling and space.
  local miss=""
  for c in debootstrap qemu-img parted zstd tar gcc make python3; do
    command -v "$c" >/dev/null 2>&1 || miss="$miss $c"
  done
  [ -z "$miss" ] && pfok "host tools present" || pfbad "missing host tools:$miss"

  local avail; avail=$(df -BG --output=avail "${BUILD_ROOT:-/root/ffn-image-build}" 2>/dev/null | tail -1 | tr -dc '0-9')
  if [ -n "$avail" ] && [ "$avail" -ge 25 ]; then pfok "${avail}G free for the build"
  else pfbad "only ${avail:-?}G free — a build needs ~25G"; fi

  # Profile sanity: the values that silently produce a dead box.
  [ -n "${FFN_SERIAL_BAUD:-}" ] && pfok "console baud ${FFN_SERIAL_BAUD}" || pfbad "profile sets no FFN_SERIAL_BAUD"
  [ -n "${FFN_MGMT_IFACE:-}" ] && pfok "mgmt port pinned to ${FFN_MGMT_IFACE}" || pfbad "profile pins no mgmt port"

  if [ "${FFN_CPLD_WDT:-no}" = yes ]; then
    pfwarn "FFN_CPLD_WDT=yes — vendor watchdog module would be installed. That is"
    pfwarn "  fine for a box you keep, but such an image MUST NOT be distributed."
  fi

  echo
  [ "$PF_FAIL" -eq 0 ] && printf '\033[32mpreflight passed\033[0m\n' \
                       || { printf '\033[31mpreflight failed (%d)\033[0m\n' "$PF_FAIL"; return 1; }
}

# =================================================================== build ====
build(){
  banner "build — ${MODEL}"
  [ "$YES" = 1 ] || echo "  (this takes a while: debootstrap + chroot provision + image assembly)"
  FFN_PROFILE="$PROFILE" "$HERE/build.sh" || die "build.sh failed"
}

find_artifact(){
  [ -n "$ARTIFACT" ] && { echo "$ARTIFACT"; return; }
  ls -t "${OUT:-$HERE/out}"/*-rootfs.tar.zst 2>/dev/null | head -1
}

# ================================================================== verify ====
verify(){
  banner "verify — ${MODEL}"
  local a; a="$(find_artifact)"
  [ -n "$a" ] || die "no rootfs artifact found; pass --artifact"
  echo "  artifact: $a"
  "$HERE/verify-image.sh" "$a" "$PROFILE"
}

# ================================================================= publish ====
publish(){
  banner "publish — ${MODEL}"
  local a; a="$(find_artifact)"
  [ -n "$a" ] || die "no rootfs artifact found; pass --artifact"

  # Never publish something that did not pass verification.
  if ! "$HERE/verify-image.sh" "$a" "$PROFILE" >/tmp/pub-verify.out 2>&1; then
    sed 's/^/    /' /tmp/pub-verify.out | tail -20
    die "refusing to publish: $a failed verification"
  fi
  echo "  verification passed; signing"

  local ver; ver="$(basename "$a" -rootfs.tar.zst)"
  python3 /opt/ffn-ngfw-v2/ffn_payload.py publish \
      --dir "$UPDATES_DIR" --kind image --file "$a" \
      --version "${MODEL}-${ver}" --notes "FFN image for ${MODEL}" \
      || die "publish failed"
  echo "  appliances can now fetch it:"
  echo "    ffn_payload.py update --url ${FFN_UPDATE_URL:-https://10.1.0.106:8444} --kind image --apply"
}

case "$STAGE" in
  preflight) preflight ;;
  build)     build ;;
  verify)    verify ;;
  publish)   publish ;;
  all)       preflight || die "preflight failed — not building"
             build
             verify   || die "verification failed — not publishing"
             publish ;;
  *) die "unknown stage: $STAGE" ;;
esac
