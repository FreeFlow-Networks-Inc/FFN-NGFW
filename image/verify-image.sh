#!/usr/bin/env bash
# verify-image.sh -- gate a built FFN image against a model profile.
#
#   verify-image.sh <rootfs.tar.zst | rootfs-dir> [profile.conf]
#
# Every check here exists because the corresponding bug actually shipped:
#
#   * an image whose root account had no password and whose admin user was
#     key-only with an empty .ssh -- unloginnable on the console, and only the
#     WebUI login had ever been tested;
#   * an image carrying the build host's config-v2.db, so every appliance built
#     from it had the same known WebUI password (the tar excluded the directory
#     `config-v2`, which does not match the file `config-v2.db`);
#   * a serial console baud that did not match the chassis, giving an unusable
#     console on a headless box;
#   * a management port chosen alphabetically rather than pinned;
#   * a WebUI whose inline script had a syntax error -- every marker you would
#     grep for is still present in the HTML, so only a parser catches it.
#
# Exit 0 only if every check passes. Nothing here writes to the image.
set -uo pipefail

IMG="${1:-}"
PROFILE="${2:-}"
[ -n "$IMG" ] || { echo "usage: $0 <rootfs.tar.zst|rootfs-dir> [profile.conf]"; exit 2; }
[ -e "$IMG" ] || { echo "no such image: $IMG"; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
[ -n "$PROFILE" ] && [ -f "$PROFILE" ] && . "$PROFILE"
: "${FFN_MODEL:=unknown}"
: "${FFN_SERIAL_BAUD:=115200}"
: "${FFN_MGMT_IFACE:=}"
: "${FFN_DP_PORTS:=}"
: "${FFN_UNITS_ENABLE:=}"

PASS=0; FAIL=0; WARN=0
ok(){   printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad(){  printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
warn(){ printf '  \033[33mWARN\033[0m  %s\n' "$*"; WARN=$((WARN+1)); }
sec(){  printf '\n\033[1m%s\033[0m\n' "$*"; }

TMP="$(mktemp -d)"
LIST="$TMP/.listing"
cleanup(){ rm -rf "$TMP"; }
trap cleanup EXIT

# ---- materialise what we need -------------------------------------------------
# Members we inspect. Missing members are a check result, not a hard error, so
# extraction failures are tolerated and existence is tested afterwards.
MEMBERS="
./etc/shadow ./etc/passwd ./etc/hostname ./etc/default/grub
./etc/ffn-ngfw/update.pub ./etc/ffn-ngfw/mgmt.conf ./etc/ffn-ngfw/update-server.conf
./opt/ffn-ngfw-v2/ffn_manager.py ./opt/ffn-ngfw-v2/ffn_payload.py
./opt/ffn-ngfw-v2/ffn_ed25519.py ./opt/ffn-ngfw-v2/ffn_jscheck.py
./opt/ffn-ngfw-v2/static/index.html
"

if [ -d "$IMG" ]; then
  MODE="directory"; ROOT="$IMG"
  ( cd "$ROOT" && find . -xdev -print ) > "$LIST" 2>/dev/null
else
  MODE="tarball"; ROOT="$TMP/root"
  mkdir -p "$ROOT"
  echo "  reading archive (one decompress pass for the listing)..."
  tar -I zstd -tf "$IMG" > "$LIST" 2>/dev/null || tar -tf "$IMG" > "$LIST" 2>/dev/null
  [ -s "$LIST" ] || { echo "could not list $IMG"; exit 2; }
  echo "  extracting inspection set..."
  # shellcheck disable=SC2086
  tar -I zstd -xf "$IMG" -C "$ROOT" $MEMBERS 2>/dev/null \
    || tar -I zstd -xf "$IMG" -C "$ROOT" $(echo "$MEMBERS" | sed 's#\./#/#g') 2>/dev/null \
    || true
  # systemd wants/ symlinks: names only, from the listing
fi

has(){ grep -qE "(^|/)$1\$|^\./$1\$|^$1\$" "$LIST"; }
inlist(){ grep -qE "$1" "$LIST"; }
f(){ echo "$ROOT/$1"; }

echo "FFN image verification"
echo "  image   : $IMG ($MODE)"
echo "  profile : ${FFN_MODEL}"

# ---- 1. the box must be loginnable -------------------------------------------
sec "1. console access"
SH="$(f etc/shadow)"
if [ -f "$SH" ]; then
  RH="$(awk -F: '$1=="root"{print $2}' "$SH")"
  case "$RH" in
    ""|"!"|"*"|"!!"|"!*")
      bad "root has NO usable password (shadow field '${RH}') -- console login impossible" ;;
    \$*) ok "root has a password hash (${RH:0:3}...)" ;;
    *)   warn "root shadow field is unrecognised: '${RH:0:12}'" ;;
  esac
  AH="$(awk -F: '$1=="admin"{print $2}' "$SH")"
  if [ -z "$AH" ]; then
    warn "no 'admin' user in shadow"
  else
    case "$AH" in
      \$*) ok "admin has a password hash" ;;
      *)   if inlist 'home/admin/\.ssh/authorized_keys'; then
             ok "admin is key-only but has authorized_keys"
           else
             bad "admin has no password AND no authorized_keys -- cannot log in"
           fi ;;
    esac
  fi
else
  bad "etc/shadow not present in the image"
fi

# ---- 2. no secrets may ship ---------------------------------------------------
sec "2. key material (must not ship)"
LEAK="$(grep -E '(update-sign\.key|/update\.key|master\.key|\.pem$|id_rsa$|id_ed25519$)' "$LIST" \
        | grep -vE 'ssl/certs|ca-certificates|/usr/lib|/usr/share|site-packages|dist-packages|cacert\.pem$' || true)"
if [ -n "$LEAK" ]; then
  bad "private key material found in the image:"
  echo "$LEAK" | sed 's/^/          /' | head -10
else
  ok "no signing seeds, shared secrets or private keys in the image"
fi

PUB="$(f etc/ffn-ngfw/update.pub)"
if [ -s "$PUB" ]; then
  P="$(tr -d '[:space:]' < "$PUB")"
  if [ ${#P} -eq 64 ]; then ok "update.pub present (ed25519 public key ${P:0:16}...)"
  else bad "update.pub is not a 32-byte hex key (len=${#P})"; fi
else
  bad "etc/ffn-ngfw/update.pub missing -- appliance cannot verify any update"
fi

# ---- 2b. vendor firmware must never ship -------------------------------------
# An owner may use firmware from their own appliance on their own box. Packaging
# it into an image would be redistributing another company's firmware, so the
# image is rejected if any of it is present.
sec "2b. vendor firmware (owner-local only)"
VEND="$(grep -E '(ffn-ngfw/vendor/|/boot/fpga/|opt/dpfs/|u-boot-[a-z0-9]+_pciboot\.bin|vmlinux-[0-9.]+-oct[0-9]-dp|pan-manifest/fpga-images)' "$LIST" || true)"
if [ -n "$VEND" ]; then
  bad "vendor firmware found in the image -- it must stay on the owner's box:"
  echo "$VEND" | sed 's/^/          /' | head -8
else
  ok "no vendor firmware in the image"
fi

# ---- 3. no baked credentials --------------------------------------------------
sec "3. per-appliance state (must not be inherited from the build host)"
for p in 'var/lib/ffn-ngfw/config-v2\.db' 'var/lib/ffn-ngfw/security\.db'; do
  if inlist "$p"; then
    bad "${p//\\/} is baked in -- every appliance would share the build host's credentials"
  else
    ok "${p//\\/} not present"
  fi
done
if inlist 'etc/ssh/ssh_host_.*_key$'; then
  bad "SSH host keys baked in -- every appliance would share one host identity"
else
  ok "no SSH host keys baked in (regenerated at first boot)"
fi

# ---- 4. console --------------------------------------------------------------
sec "4. serial console (headless chassis)"
G="$(f etc/default/grub)"
if [ -f "$G" ]; then
  if grep -q "ttyS0,${FFN_SERIAL_BAUD}n8" "$G"; then
    ok "grub console pinned to ttyS0,${FFN_SERIAL_BAUD}n8"
  else
    bad "grub console does not match profile baud ${FFN_SERIAL_BAUD}: $(grep -o 'ttyS0,[0-9]*n8' "$G" | head -1 | sed 's/^/found /')"
  fi
  grep -q 'quiet' "$G" && warn "'quiet' is set -- boot messages hidden on a box with no video" \
                       || ok "'quiet' not set (boot progress visible on serial)"
else
  bad "etc/default/grub missing"
fi

# ---- 5. management port -------------------------------------------------------
sec "5. management interface"
M="$(f etc/ffn-ngfw/mgmt.conf)"
if [ -n "$FFN_MGMT_IFACE" ]; then
  if [ -f "$M" ] && grep -q "$FFN_MGMT_IFACE" "$M"; then
    ok "mgmt.conf pins $FFN_MGMT_IFACE ($(tr '\n' ' ' < "$M" | cut -c1-60))"
  else
    bad "mgmt.conf does not pin $FFN_MGMT_IFACE -- port may be chosen alphabetically"
  fi
else
  warn "profile sets no FFN_MGMT_IFACE; skipping"
fi

# ---- 6. dataplane -------------------------------------------------------------
sec "6. dataplane"
DPU="$ROOT/etc/systemd/system/ffn-dp-afpacket.service"
if [ -n "$FFN_DP_PORTS" ]; then
  if inlist 'ffn-dp-afpacket\.service'; then
    ok "ffn-dp-afpacket.service present"
    if [ -f "$DPU" ]; then
      miss=""
      for p in $FFN_DP_PORTS; do grep -q -- "$p" "$DPU" || miss="$miss $p"; done
      [ -z "$miss" ] && ok "bound to profile ports: $FFN_DP_PORTS" \
                     || bad "unit does not reference:$miss"
    else
      warn "unit not in the inspection set; port binding unverified"
    fi
  else
    bad "ffn-dp-afpacket.service missing -- no dataplane on this image"
  fi
fi

# ---- 6b. chassis log volume --------------------------------------------
# The log RAID is useless without mdadm in the image and the discovery
# service enabled, and both are easy to forget.
sec "6b. chassis log volume"
if inlist '(usr/)?sbin/mdadm$'; then
  ok "mdadm present (log RAID can be assembled)"
else
  bad "mdadm MISSING -- the internal log drives would stay invisible"
fi
if inlist 'ffn-logvol\.sh$'; then
  ok "ffn-logvol.sh present"
else
  bad "ffn-logvol.sh missing -- no log-volume discovery"
fi
if inlist 'multi-user\.target\.wants/ffn-logvol\.service'; then
  ok "ffn-logvol enabled at boot"
else
  warn "ffn-logvol not enabled -- logs will stay on the system disk"
fi

# ---- 7. services --------------------------------------------------------------
sec "7. enabled services"
for u in $FFN_UNITS_ENABLE; do
  if inlist "(multi-user|sysinit)\.target\.wants/${u}\.service"; then
    ok "$u enabled"
  elif inlist "${u}\.service"; then
    bad "$u present but NOT enabled"
  else
    bad "$u missing from the image"
  fi
done

# ---- 8. FFN code ---------------------------------------------------------------
sec "8. FFN software"
for p in ffn_manager.py ffn_payload.py ffn_ed25519.py static/index.html; do
  [ -s "$(f opt/ffn-ngfw-v2/$p)" ] && ok "$p present" || bad "$p missing"
done

if command -v python3 >/dev/null 2>&1; then
  MGR="$(f opt/ffn-ngfw-v2/ffn_manager.py)"
  if [ -s "$MGR" ]; then
    python3 -m py_compile "$MGR" 2>/dev/null && ok "ffn_manager.py compiles" \
                                             || bad "ffn_manager.py does NOT compile"
  fi
  IDX="$(f opt/ffn-ngfw-v2/static/index.html)"
  JS="$(f opt/ffn-ngfw-v2/ffn_jscheck.py)"
  [ -s "$JS" ] || JS="$HERE/../opt/ffn_jscheck.py"   # published repo layout
  [ -s "$JS" ] || JS="$HERE/../ffn_jscheck.py"
  [ -s "$JS" ] || JS="/opt/ffn-ngfw-v2/ffn_jscheck.py"
  if [ -s "$IDX" ] && [ -s "$JS" ]; then
    if python3 "$JS" "$IDX" >"$TMP/js.out" 2>&1; then
      ok "WebUI JavaScript parses ($(grep -o '[0-9]* function declarations' "$TMP/js.out" | head -1))"
    else
      bad "WebUI JavaScript has structural errors -- the UI would be blank:"
      sed 's/^/          /' "$TMP/js.out" | head -6
    fi
  else
    warn "WebUI or jscheck unavailable; JS not verified"
  fi
fi

# ---- summary ------------------------------------------------------------------
printf '\n\033[1m%d passed, %d failed, %d warnings\033[0m\n' "$PASS" "$FAIL" "$WARN"
[ "$FAIL" -eq 0 ] || { echo -e "\033[31mIMAGE REJECTED\033[0m"; exit 1; }
echo -e "\033[32mIMAGE ACCEPTED for ${FFN_MODEL}\033[0m"
