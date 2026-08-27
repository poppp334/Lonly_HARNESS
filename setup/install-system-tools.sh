#!/usr/bin/env bash
# ============================================================================
# LONLY system-tools installer — Arch / Omarchy
# ============================================================================
# Run as your normal user (NOT root — yay refuses to run as root):
#
#   ./setup/install-system-tools.sh
#
# You will be asked for your sudo password a few times. `sudo -v` up front
# caches the credential so yay/pacman prompts stay minimal.
#
# Split of responsibilities (keeps exactly one owner per tool — no duplicates):
#   * THIS SCRIPT (root installs)  : compiled tools + Ruby/Perl tools + metasploit + netexec
#   * venv ~/pentest_env (already done) : sqlmap, impacket
#   * user-level ~/.local (already done): ollama (binary + user systemd unit)
#
# Wordlists: official repos have no wordlists package here, so seclists (AUR)
# is the single source. The "Kali path compatibility" section below symlinks
# the Kali-style paths LONLY's defaults expect onto seclists/metasploit paths
# so pentest_agent.py works unchanged on Kali AND Arch.
# ============================================================================
set -euo pipefail

sudo -v

echo "== 1/4: official repos (pacman) =="
sudo pacman -Sy --needed --noconfirm \
  git base-devel \
  nmap nikto gobuster hydra openldap openbsd-netcat \
  metasploit masscan rustscan wpscan exploitdb

echo "== 2/4: AUR (yay) =="
yay -S --needed --noconfirm \
  ffuf whatweb enum4linux peass-ng kerbrute-bin seclists netexec

echo "== 3/4: Kali-path wordlist compatibility (symlink shims) =="
sudo mkdir -p /usr/share/wordlists/dirbuster /usr/share/wordlists/dirb \
  /usr/share/wordlists/metasploit /usr/share/wordlists/seclists/Usernames
# gobuster default: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# (seclists 2026.1 renamed the list to DirBuster-2007_*)
sudo ln -sf /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# ffuf default: /usr/share/wordlists/dirb/common.txt
sudo ln -sf /usr/share/seclists/Discovery/Web-Content/common.txt \
  /usr/share/wordlists/dirb/common.txt
# hydra default user list: /usr/share/wordlists/metasploit/namelist.txt
# (Arch's metasploit package installs under /opt/metasploit)
if [ -f /opt/metasploit/data/wordlists/namelist.txt ]; then
  sudo ln -sf /opt/metasploit/data/wordlists/namelist.txt \
    /usr/share/wordlists/metasploit/namelist.txt
fi
# kerbrute default: /usr/share/wordlists/seclists/Usernames/top-usernames-short.txt
# (AUR seclists ships this list as top-usernames-shortlist.txt)
sudo ln -sf /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  /usr/share/wordlists/seclists/Usernames/top-usernames-short.txt
# knowledge/kerberoasting.md references /usr/share/wordlists/rockyou.txt
if [ -f /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ]; then
  sudo ln -sf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt \
    /usr/share/wordlists/rockyou.txt
fi
# linpeas: LONLY default is /usr/share/peass/linpeas/linpeas.sh, but the AUR
# peass-ng package installs to /usr/share/peass-ng/linux/linpeas.sh
if [ -f /usr/share/peass-ng/linux/linpeas.sh ]; then
  sudo mkdir -p /usr/share/peass/linpeas
  sudo ln -sf /usr/share/peass-ng/linux/linpeas.sh \
    /usr/share/peass/linpeas/linpeas.sh
fi

echo "== 4/4: verification =="
declare -A BINS=(
  [nmap]=nmap [nikto]=nikto [gobuster]=gobuster [hydra]=hydra
  [ldapsearch]=ldapsearch [nc]=nc [msfconsole]=msfconsole
  [masscan]=masscan [rustscan]=rustscan [wpscan]=wpscan
  [searchsploit]=searchsploit [ffuf]=ffuf [whatweb]=whatweb
  [enum4linux]=enum4linux [kerbrute]=kerbrute
)
fails=0
for name in "${!BINS[@]}"; do
  if command -v "${BINS[$name]}" >/dev/null 2>&1; then
    echo "  OK   $name -> $(command -v "${BINS[$name]}")"
  else
    echo "  FAIL $name"
    fails=$((fails + 1))
  fi
done
if [ -f /usr/share/peass/linpeas/linpeas.sh ]; then
  echo "  OK   linpeas -> /usr/share/peass/linpeas/linpeas.sh"
else
  echo "  FAIL linpeas (peass-ng script not found)"
  fails=$((fails + 1))
fi

echo "  -- wordlist shims --"
SHIMS=(
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  /usr/share/wordlists/dirb/common.txt
  /usr/share/wordlists/metasploit/namelist.txt
  /usr/share/wordlists/seclists/Usernames/top-usernames-short.txt
  /usr/share/wordlists/rockyou.txt
)
for shim in "${SHIMS[@]}"; do
  if [ -e "$shim" ]; then
    echo "  OK   $shim -> $(readlink "$shim")"
  else
    echo "  FAIL $shim"
    fails=$((fails + 1))
  fi
done

echo
echo "Remaining pieces live outside this script:"
echo "  venv tools:  ~/pentest_env/bin/{sqlmap,impacket-secretsdump,...}"
echo "  ollama:      ~/.local/bin/ollama (user service: systemctl --user status ollama)"
echo "  RAG store:   run '~/pentest_env/bin/python ingest_knowledge.py' in the project"
if [ "$fails" -gt 0 ]; then
  echo "RESULT: $fails tool(s) missing — investigate before running LONLY."
  exit 1
fi
echo "RESULT: all system tools OK."
