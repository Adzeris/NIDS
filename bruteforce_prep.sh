#!/usr/bin/env bash
set -euo pipefail

# Defender prep helper for brute-force testing in the NIDS lab.
# Safe to run repeatedly (idempotent).
#
# Usage:
#   bash bruteforce_prep.sh
#   LAB_USER=myuser LAB_PASS='MyPass123!' bash bruteforce_prep.sh
#
# Optional env vars:
#   LAB_USER  (default: nids_test_user)
#   LAB_PASS  (default: LabPass123!)

LAB_USER="${LAB_USER:-nids_test_user}"
LAB_PASS="${LAB_PASS:-LabPass123!}"

run_priv() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

ensure_pkg() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "[OK] Package already installed: $pkg"
    return
  fi
  echo "[INFO] Installing package: $pkg"
  run_priv apt-get update -y
  run_priv apt-get install -y "$pkg"
}

set_sshd_option() {
  local key="$1"
  local value="$2"
  local cfg="/etc/ssh/sshd_config"
  local esc_key
  esc_key="$(printf '%s' "$key" | sed 's/[.[\*^$()+?{|]/\\&/g')"

  if run_priv grep -Eq "^[[:space:]]*${esc_key}[[:space:]]+${value}[[:space:]]*$" "$cfg"; then
    echo "[OK] $key already set to $value"
    return
  fi

  if run_priv grep -Eq "^[[:space:]]*#?[[:space:]]*${esc_key}[[:space:]]+" "$cfg"; then
    run_priv sed -i "s|^[[:space:]]*#\\?[[:space:]]*${esc_key}[[:space:]].*|${key} ${value}|g" "$cfg"
  else
    run_priv bash -lc "printf '\n%s %s\n' '$key' '$value' >> '$cfg'"
  fi
  echo "[INFO] Set $key $value"
}

echo "== Defender prep for NIDS brute-force tests =="
echo "[INFO] Lab user: $LAB_USER"

ensure_pkg openssh-server

if id -u "$LAB_USER" >/dev/null 2>&1; then
  echo "[OK] User exists: $LAB_USER"
else
  echo "[INFO] Creating user: $LAB_USER"
  run_priv useradd -m -s /bin/bash "$LAB_USER"
fi

echo "[INFO] Setting password for $LAB_USER"
run_priv bash -lc "echo '$LAB_USER:$LAB_PASS' | chpasswd"

set_sshd_option "PasswordAuthentication" "yes"
set_sshd_option "KbdInteractiveAuthentication" "yes"

echo "[INFO] Enabling + restarting ssh service"
run_priv systemctl enable --now ssh
run_priv systemctl restart ssh

if run_priv systemctl is-active --quiet ssh; then
  echo "[OK] ssh service is active"
else
  echo "[WARN] ssh service is not active"
fi

if run_priv bash -lc "ss -tulpn | grep -Eq ':22([[:space:]]|$)'"; then
  echo "[OK] Port 22 is listening"
else
  echo "[WARN] Port 22 does not appear to be listening"
fi

DEF_IFACE="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
DEF_IP="$(ip -4 -o addr show dev "$DEF_IFACE" 2>/dev/null | awk 'NR==1{split($4,a,\"/\"); print a[1]}')"

echo
echo "== Ready summary =="
echo "Defender interface : ${DEF_IFACE:-unknown}"
echo "Defender IP        : ${DEF_IP:-unknown}"
echo "SSH user           : $LAB_USER"
echo "SSH pass           : $LAB_PASS"
echo
echo "You can now run brute-force tests from attacker GUI."
