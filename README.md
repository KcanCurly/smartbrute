Small script to bruteforce AD ldap without locking accounts.

There is help menu, read it.

time-based-tries example : --time-based-tries "3:18:00-20:00" means application will do 3 tries if time in UTC is between 18:00 and 20:00

You can find pattern example in ./smartbrute/patterns.toml. Application will search current directory for toml file otherwise it will use default one.

Install with
pipx install git+https://github.com/kcancurly/smartbrute

Info:\
https://learn.microsoft.com/en-us/archive/technet-wiki/32490.active-directory-bad-passwords-and-account-lockout

You should give PDC as your server, you can find it with;\
`nslookup -type=SRV _ldap._tcp.pdc._msdcs.DOMAIN_NAME \[DNS IP\]`\
or\
`dnsrecon -d DOMAIN_NAME \[-ns DNS IP\]`

record should look like this:
_ldap._tcp.pdc._msdcs.example.local