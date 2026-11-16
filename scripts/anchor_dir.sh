#!/usr/bin/env sh
# Prepare the audit anchor directory (bind mount of audit_anchor, outside the
# database volume): 700 for the host user plus rwx for uid 10002 through an
# ACL; never 777. The anchor files inside are 0644, so the host user can read
# them while the directory keeps everyone else out.
#   scripts/anchor_dir.sh [--strict] DIR
# Used by init_secrets.sh and, before the retire, by make reset/fclean (З-9):
# a directory Docker creates itself for the bind mount belongs to root and
# audit_anchor (uid 10002) could never write to it.
# --strict (make reset/fclean): exit 1 instead of a warning when uid 10002
# cannot get write access, when the directory belongs to someone else (e.g.
# root 755 after Docker created it), or when the result is not 700 + ACL
# u:10002:rwx (or, as root, owner 10002 with 700).
set -eu
AUDIT_UID=10002
strict=no
if [ "${1:-}" = --strict ]; then strict=yes; shift; fi
anchor_dir="${1:?usage: anchor_dir.sh [--strict] DIR}"

if [ ! -d "$anchor_dir" ]; then
  mkdir -p "$anchor_dir"
  chmod 700 "$anchor_dir"
  echo "created $anchor_dir (audit anchors and chain registry; keep it, do not git clean it)"
fi
if [ -O "$anchor_dir" ]; then
  chmod 700 "$anchor_dir"
  if command -v setfacl >/dev/null 2>&1 && setfacl -m "u:$AUDIT_UID:rwx" "$anchor_dir" 2>/dev/null; then
    :
  elif [ "$(id -u)" = 0 ]; then
    chown "$AUDIT_UID:$AUDIT_UID" "$anchor_dir"
  else
    echo "warning $anchor_dir: cannot grant write access to audit_anchor (uid $AUDIT_UID)." >&2
    echo "        No anchors will be written and audit_anchor stays unhealthy. Install the acl package and rerun," >&2
    echo "        or: sudo setfacl -m u:$AUDIT_UID:rwx $anchor_dir" >&2
    [ "$strict" = no ] || exit 1
  fi
else
  if [ "$strict" = yes ] && ! { [ "$(id -u)" = 0 ] && [ "$(stat -c %u "$anchor_dir")" = "$AUDIT_UID" ]; }; then
    echo "error   $anchor_dir belongs to uid $(stat -c %u "$anchor_dir") (mode $(stat -c %a "$anchor_dir")), not to you ($(id -u))." >&2
    echo "        audit_anchor (uid $AUDIT_UID) may not be able to write there; fix it by hand, e.g." >&2
    echo "        sudo chown $(id -u):$(id -g) $anchor_dir && sh scripts/anchor_dir.sh $anchor_dir" >&2
    exit 1
  fi
  echo "note    $anchor_dir is not owned by you; permissions left as they are"
fi

if [ "$strict" = yes ]; then
  # check the result, not only the commands: no access for group/other, and
  # uid 10002 can write (ACL entry, or the owner when root chowned it)
  mode="$(stat -c %a "$anchor_dir")"
  owner="$(stat -c %u "$anchor_dir")"
  ok=no
  if [ "$owner" = "$AUDIT_UID" ] && [ "$mode" = 700 ]; then
    ok=yes
  elif command -v getfacl >/dev/null 2>&1; then
    acl="$(getfacl -cpn "$anchor_dir" 2>/dev/null || true)"
    if printf '%s\n' "$acl" | grep -qx "user:$AUDIT_UID:rwx" \
        && printf '%s\n' "$acl" | grep -qx "group::---" \
        && printf '%s\n' "$acl" | grep -qx "other::---" \
        && ! printf '%s\n' "$acl" | grep -E '^(user|group):[^:]+:' | grep -vqx "user:$AUDIT_UID:rwx"; then
      ok=yes
    fi
  fi
  if [ "$ok" != yes ]; then
    echo "error   $anchor_dir is not 700 + ACL u:$AUDIT_UID:rwx (mode $mode, owner uid $owner)." >&2
    exit 1
  fi
fi
