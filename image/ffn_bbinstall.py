#!/usr/bin/env python3
"""Give the CP the tools it lacks, without shadowing what it already has.

The CP's PATH is /usr/local/cp:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin, so
/usr/local/bin comes BEFORE the real /bin. Blanket-linking every busybox applet
there would replace the vendor's mount, ps, ifconfig etc. with busybox versions --
a good way to break an NFS-rooted system. So link ONLY applets that resolve to
nothing today, and leave every existing binary alone.

Runs on the MP: the CP's root filesystem IS /opt/dpfs here (served over NFS), so
this is plain local file work.
"""
import os

DPFS = "/opt/dpfs"
DEST_REL = "usr/local/bin"
BB = "busybox"                     # relative link target, sits in the same dir
SEARCH = ["usr/local/cp", "usr/local/bin", "usr/bin", "bin", "usr/sbin", "sbin"]
# Never link these even if absent: they are core to how the CP boots and mounts,
# and a busybox variant could subtly differ where it matters most.
NEVER = {"mount", "umount", "init", "chroot", "pivot_root", "insmod", "rmmod",
         "modprobe", "reboot", "halt", "poweroff", "sh", "bash", "busybox"}

listing = os.path.join(DPFS, "tmp", "bb.list")
applets = [a.strip() for a in open(listing).read().split() if a.strip()]
dest = os.path.join(DPFS, DEST_REL)
os.makedirs(dest, exist_ok=True)


def present(name):
    for d in SEARCH:
        p = os.path.join(DPFS, d, name)
        if os.path.exists(p) or os.path.islink(p):
            return True
    return False


made, skipped, held = [], 0, 0
for a in sorted(set(applets)):
    if "/" in a:
        continue
    if a in NEVER:
        held += 1
        continue
    if present(a):
        skipped += 1
        continue
    try:
        os.symlink(BB, os.path.join(dest, a))
        made.append(a)
    except OSError as e:
        print("  skip %s: %s" % (a, e))

print("applets in binary : %d" % len(set(applets)))
print("already present   : %d  (untouched -- no shadowing)" % skipped)
print("deliberately held : %d  (%s)" % (held, " ".join(sorted(NEVER))))
print("newly available   : %d" % len(made))
want = ("sed", "tar", "xargs", "vi", "less", "awk", "wget", "nc", "top", "ps",
        "diff", "patch", "cmp", "strings", "hexdump", "base64", "killall",
        "free", "gzip", "bzip2", "unzip", "nslookup", "traceroute", "telnet",
        "vlock", "watch", "ash")
print("key tools gained  : %s" % " ".join(t for t in want if t in made))
