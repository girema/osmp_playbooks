#!/usr/bin/env python3
# ==============================================================
#  ad_user.py
#  Purpose : Enable/disable/reset AD users and manage group membership via LDAP (Kerberos SASL/GSSAPI)
#  Version : 1.2 (normalization + per-user prints + aggregated exit)
#  Requires: python3-ldap, kinit + keytab with a principal that has modify privileges
# ==============================================================

import argparse
import os
import subprocess
import sys
from typing import List, Optional

try:
    import ldap
    import ldap.sasl
    from ldap.filter import escape_filter_chars
except Exception as e:
    print(f"? Failed to import python-ldap: {e}", file=sys.stderr)
    sys.exit(1)

# === Configuration ===
LDAP_SERVER   = os.environ.get("LDAP_SERVER", "ldap://dc1.example.local")
LDAP_BASE_DN  = os.environ.get("LDAP_BASE_DN", "DC=example,DC=local")
KEYTAB        = os.environ.get("KEYTAB", "/etc/krb5.keytab")
PRINCIPAL     = os.environ.get("PRINCIPAL", "svc_siem@EXAMPLE.LOCAL")

# --- Username normalization to sAMAccountName ---
# Accepted formats:
#   example\\user, example.local\\user, user@example, user@example.local, user
# Rejected: domains other than example/example.local, and machine accounts (ending with $)
ALLOWED_DOMAINS = {"example", "example.local"}

def normalize_username_input(u: str):
    """Return (sam, None) on success or (None, reason) on failure."""
    if u is None:
        return None, "empty"
    u = u.strip()
    if not u:
        return None, "empty"
    if u.endswith("$"):
        return None, "machine"
    if "\\" in u:
        prefix, name = u.split("\\", 1)
        if prefix.lower() not in ALLOWED_DOMAINS:
            return None, "bad_prefix"
        return name, None
    if "@" in u:
        name, suffix = u.split("@", 1)
        if suffix.lower() not in ALLOWED_DOMAINS:
            return None, "bad_suffix"
        return name, None
    return u, None  # plain sAM

# ===== Helpers =====

def kinit_with_keytab(keytab: str, principal: str) -> None:
    """Run kinit -k -t KEYTAB PRINCIPAL."""
    if not keytab:
        return
    if not os.path.isfile(keytab):
        print(f"Keytab {keytab} not found, aborting")
        sys.exit(1)
    print(f"==> Initializing Kerberos from keytab {keytab} (principal: {principal})")
    try:
        subprocess.run(["kinit", "-k", "-t", keytab, principal],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("kinit failed, aborting")
        if e.stderr:
            sys.stderr.write(e.stderr.decode(errors="ignore"))
        sys.exit(1)

def connect_ldap(uri: str):
    """SASL/GSSAPI bind using current Kerberos TGT."""
    conn = ldap.initialize(uri)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.protocol_version = 3
    try:
        auth = ldap.sasl.gssapi("")
        conn.sasl_interactive_bind_s("", auth)
    except ldap.LDAPError as e:
        print("ldap_sasl_interactive_bind: failed", file=sys.stderr)
        print(e, file=sys.stderr)
        sys.exit(1)
    return conn

def decode_first(attrs: dict, key: str) -> str:
    vals = attrs.get(key)
    if not vals:
        return ""
    v = vals[0]
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="ignore")
    return str(v)

def decode_multi(attrs: dict, key: str) -> List[str]:
    vals = attrs.get(key) or []
    out = []
    for v in vals:
        if isinstance(v, bytes):
            out.append(v.decode("utf-8", errors="ignore"))
        else:
            out.append(str(v))
    return out

def search_one_dn(conn, base_dn: str, filt: str, attrs: Optional[List[str]] = None):
    """Return (dn, attrs) of the first match; otherwise (None, None)."""
    try:
        res = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filt, attrs)
    except ldap.LDAPError as e:
        print(f"? LDAP search failed for filter {filt}: {e}", file=sys.stderr)
        return None, None

    if not res:
        return None, None
    for dn, a in res:
        if dn:
            return dn, a
    return None, None

def convert_windows_filetime_to_utc_str(val: str) -> str:
    """
    Convert AD FILETIME (100-ns ticks since 1601-01-01) to a UTC string.
    Very large values are treated as Never/Disabled.
    """
    try:
        n = int(val)
    except Exception:
        return "Never/Disabled"
    if n > 9_000_000_000_000_000_000:
        return "Never/Disabled"
    if n > 100_000_000_000_000_000:
        epoch_seconds = (n // 10_000_000) - 11644473600
        try:
            from datetime import datetime, timezone
            return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "Never/Disabled"
    return "Never/Disabled"

# ===== Actions =====

def do_info(conn, base_dn: str, users: List[str]) -> int:
    for username in users:
        username = username.strip()
        if not username:
            continue
        print(f"Username: {username}")
        filt = f"(sAMAccountName={escape_filter_chars(username)})"
        dn, attrs = search_one_dn(conn, base_dn, filt, attrs=[
            "cn","mail","title","department","manager","memberOf",
            "whenCreated","whenChanged","userAccountControl",
            "lastLogonTimestamp","pwdLastSet","badPwdCount","badPasswordTime",
            "accountExpires","description","distinguishedName"
        ])

        if dn is None:
            print("CN: ")
            print("Distinguished Name: ")
            print("UserAccountControl: ")
            print("Bad Password Count: ")
            print("Bad Password Time (UTC): Never/Disabled")
            print("Member Of: ")
            print("pwdLastSet (UTC): Never/Disabled")
            print("lastLogonTimestamp (UTC): Never/Disabled")
            print("accountExpires (UTC): Never/Disabled")
            print("-----------------")
            continue

        cn          = decode_first(attrs, "cn")
        uac         = decode_first(attrs, "userAccountControl")
        badcnt      = decode_first(attrs, "badPwdCount")
        badtime     = decode_first(attrs, "badPasswordTime")
        memberof    = decode_multi(attrs, "memberOf")
        dn_attr     = decode_first(attrs, "distinguishedName")
        pwdlastset  = decode_first(attrs, "pwdLastSet")
        llt         = decode_first(attrs, "lastLogonTimestamp")
        accexp      = decode_first(attrs, "accountExpires")

        print(f"CN: {cn}")
        print(f"Distinguished Name: {dn_attr}")
        print(f"UserAccountControl: {uac}")
        print(f"Bad Password Count: {badcnt}")
        print(f"Bad Password Time (UTC): {convert_windows_filetime_to_utc_str(badtime)}")
        if memberof:
            print("Member Of: " + "\n".join(memberof))
        else:
            print("Member Of: ")
        print(f"pwdLastSet (UTC): {convert_windows_filetime_to_utc_str(pwdlastset)}")
        print(f"lastLogonTimestamp (UTC): {convert_windows_filetime_to_utc_str(llt)}")
        print(f"accountExpires (UTC): {convert_windows_filetime_to_utc_str(accexp)}")
        print("-----------------")
    return 0

def modify_user_uac(conn, base_dn: str, username: str, new_uac: int) -> bool:
    filt = f"(sAMAccountName={escape_filter_chars(username)})"
    dn, _ = search_one_dn(conn, base_dn, filt, attrs=['dn'])
    print(f"Resolved DN for '{username}': {dn or ''}")
    if not dn:
        print(f"? User '{username}' not found in AD")
        return False
    try:
        conn.modify_s(dn, [(ldap.MOD_REPLACE, 'userAccountControl', [str(new_uac).encode('utf-8')])])
        return True
    except ldap.LDAPError as e:
        print(f"? Action failed for '{username}': {e}")
        return False

def reset_password_flag(conn, base_dn: str, username: str) -> bool:
    filt = f"(sAMAccountName={escape_filter_chars(username)})"
    dn, _ = search_one_dn(conn, base_dn, filt, attrs=['dn'])
    print(f"Resolved DN for '{username}': {dn or ''}")
    if not dn:
        print(f"? User '{username}' not found in AD")
        return False
    try:
        conn.modify_s(dn, [(ldap.MOD_REPLACE, 'pwdLastSet', [b'0'])])
        return True
    except ldap.LDAPError as e:
        print(f"? Action failed for '{username}': {e}")
        return False

def find_group_dn(conn, base_dn: str, cn: str) -> Optional[str]:
    gfilt = f"(cn={escape_filter_chars(cn)})"
    gdn, _ = search_one_dn(conn, base_dn, gfilt, attrs=['dn'])
    return gdn

def add_to_group(conn, base_dn: str, username: str, group_cn: str) -> bool:
    if not group_cn:
        print("? Missing --addgroup parameter.")
        return False
    gdn = find_group_dn(conn, base_dn, group_cn)
    if not gdn:
        print(f"? Group '{group_cn}' not found in AD")
        return False

    ufilt = f"(sAMAccountName={escape_filter_chars(username)})"
    udn, _ = search_one_dn(conn, base_dn, ufilt, attrs=['dn'])
    print(f"Resolved DN for '{username}': {udn or ''}")
    if not udn:
        print(f"? User '{username}' not found in AD")
        return False

    try:
        conn.modify_s(gdn, [(ldap.MOD_ADD, 'member', [udn.encode('utf-8')])])
        return True
    except ldap.LDAPError as e:
        print(f"? Action failed for '{username}': {e}")
        return False

def remove_from_group(conn, base_dn: str, username: str, group_cn: str) -> bool:
    if not group_cn:
        print("? Missing --removegroup parameter.")
        return False
    gdn = find_group_dn(conn, base_dn, group_cn)
    if not gdn:
        print(f"? Group '{group_cn}' not found in AD")
        return False

    ufilt = f"(sAMAccountName={escape_filter_chars(username)})"
    udn, _ = search_one_dn(conn, base_dn, ufilt, attrs=['dn'])
    print(f"Resolved DN for '{username}': {udn or ''}")
    if not udn:
        print(f"? User '{username}' not found in AD")
        return False

    try:
        conn.modify_s(gdn, [(ldap.MOD_DELETE, 'member', [udn.encode('utf-8')])])
        return True
    except ldap.LDAPError as e:
        print(f"? Action failed for '{username}': {e}")
        return False

# ===== Main =====

def main():
    parser = argparse.ArgumentParser(
        description="AD response actions via LDAP (Kerberos/GSSAPI), Python port of Bash script"
    )
    parser.add_argument("--action", required=True,
                        choices=["lock", "unlock", "reset", "addgroup", "removegroup", "info"])
    parser.add_argument("--users", required=True,
                        help="Comma-separated list of usernames (example\\user | user@example | sAM)")
    parser.add_argument("--addgroup", help="Group CN to add user to")
    parser.add_argument("--removegroup", help="Group CN to remove user from")
    args = parser.parse_args()

    # Kerberos init
    kinit_with_keytab(KEYTAB, PRINCIPAL)

    # LDAP bind
    conn = connect_ldap(LDAP_SERVER)

    # Parse and normalize users
    raw_users = [u.strip() for u in args.users.split(",") if u.strip()]
    normalized: List[str] = []
    failures = 0

    for raw in raw_users:
        print(f"Raw input: {raw!r}")
        sam, err = normalize_username_input(raw)
        if err == "empty":
            print("? Skipping empty username")
            print("exit 2")
            failures += 1
            continue
        if err == "machine":
            print(f"? Skipping user '{raw}' (machine account)")
            print("exit 2")
            failures += 1
            continue
        if err in ("bad_prefix", "bad_suffix"):
            print(f"? Skipping user '{raw}' (unsupported domain)")
            print("exit 2")
            failures += 1
            continue
        normalized.append(sam)

    if args.action == "info":
        rc = do_info(conn, LDAP_BASE_DN, normalized)
        # If some usernames failed normalization, treat it as a partial failure
        if failures > 0:
            sys.exit(2)
        sys.exit(rc)

    if not normalized and failures == 0:
        print("? No valid users after normalization.")
        sys.exit(2)

    # Execute actions per user; print per-user status; aggregate final exit
    for username in normalized:
        print(f"==> Processing user: {username} (action: {args.action})")
        ok = False
        if args.action == "unlock":
            ok = modify_user_uac(conn, LDAP_BASE_DN, username, new_uac=512)
            if ok:
                print(f"? User '{username}' successfully enabled.")
                print("exit 0")
            else:
                print("exit 2")
                failures += 1
        elif args.action == "lock":
            ok = modify_user_uac(conn, LDAP_BASE_DN, username, new_uac=514)
            if ok:
                print(f"?? User '{username}' successfully disabled.")
                print("exit 0")
            else:
                print("exit 2")
                failures += 1
        elif args.action == "reset":
            ok = reset_password_flag(conn, LDAP_BASE_DN, username)
            if ok:
                print(f"?? User '{username}' must change password at next login.")
                print("exit 0")
            else:
                print("exit 2")
                failures += 1
        elif args.action == "addgroup":
            ok = add_to_group(conn, LDAP_BASE_DN, username, args.addgroup)
            if ok:
                print(f"? User '{username}' added to group '{args.addgroup}'.")
                print("exit 0")
            else:
                print("exit 2")
                failures += 1
        elif args.action == "removegroup":
            ok = remove_from_group(conn, LDAP_BASE_DN, username, args.removegroup)
            if ok:
                print(f"? User '{username}' removed from group '{args.removegroup}'.")
                print("exit 0")
            else:
                print("exit 2")
                failures += 1

    # Final exit: any failure -> 2, else 0
    if failures > 0:
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
