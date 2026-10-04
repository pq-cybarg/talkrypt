#!/usr/bin/env bash
# Read-only audit for OS-level age-verification / age-signal plumbing on THIS
# machine (see docs/privacy/age-verification-removal.md). Reports only; it
# changes nothing. Companion to the Ageless Linux effort.
#
#   bash scripts/privacy/audit-age-signals.sh
#
# Exit 0 = no age signal found; 1 = a birthDate or age-collection surface present.
set -uo pipefail
found=0
say() { printf '%s\n' "$*"; }

say "== talkrypt age-signal audit (read-only) =="

# 1. init system: systemd-free distros have no birthDate field at all.
if [ -d /run/systemd/system ]; then
  say "[info] init: systemd (has the userdb birthDate field)"
  SYSTEMD=1
else
  say "[ok]   init: non-systemd — no userdb birthDate plumbing exists here"
  SYSTEMD=0
fi

# 2. Is a birthDate actually set on the current user's record?
if [ "$SYSTEMD" = 1 ] && command -v userdbctl >/dev/null 2>&1; then
  if userdbctl user "$(id -un)" 2>/dev/null | grep -qi 'birth'; then
    say "[WARN] a birthDate is SET on your user record:"
    userdbctl user "$(id -un)" 2>/dev/null | grep -i 'birth' | sed 's/^/        /'
    say "       -> see docs/privacy/age-verification-removal.md to clear/avoid it"
    found=1
  else
    say "[ok]   no birthDate set on your user record"
  fi
fi

# 3. userdb drop-ins that could inject a birthDate.
for d in /etc/userdb /run/userdb /run/host/userdb; do
  [ -d "$d" ] || continue
  if grep -rliE 'birth' "$d" 2>/dev/null | head -1 | grep -q .; then
    say "[WARN] birthDate referenced in a userdb drop-in under $d:"
    grep -rliE 'birth' "$d" 2>/dev/null | sed 's/^/        /'
    found=1
  fi
done

# 4. The proposed cross-desktop interface org.freedesktop.AgeVerification1
#    (self-declared age brackets), plus any age/parental daemon on the bus.
if command -v busctl >/dev/null 2>&1; then
  if busctl --no-pager list 2>/dev/null | grep -qi 'AgeVerification1'; then
    say "[WARN] org.freedesktop.AgeVerification1 is present on the bus:"
    busctl --no-pager list 2>/dev/null | grep -i 'AgeVerification1' | sed 's/^/        /'
    found=1
  fi
  if busctl --no-pager list 2>/dev/null | grep -iE 'age|parental|ageassur' | grep -vi 'AgeVerification1' | grep -q .; then
    say "[WARN] a bus name mentioning age/parental is present:"
    busctl --no-pager list 2>/dev/null | grep -iE 'age|parental|ageassur' | grep -vi 'AgeVerification1' | sed 's/^/        /'
    found=1
  fi
fi
if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files 2>/dev/null | grep -iE 'age-?verif|age-?assur|parental' | grep -q .; then
    say "[WARN] a unit mentioning age-verification/parental is installed:"
    systemctl list-unit-files 2>/dev/null | grep -iE 'age-?verif|age-?assur|parental' | sed 's/^/        /'
    found=1
  fi
fi

if [ "$found" = 0 ]; then
  say "[PASS] no age-collection / age-signal surface detected on this machine."
else
  say "[FAIL] age-signal surface(s) found above — see the removal guide."
fi
exit "$found"
