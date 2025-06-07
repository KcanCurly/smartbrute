Small script to bruteforce AD ldap without locking accounts.

You can find pattern example in ./smartbrute/patterns.toml. Application will search current directory for toml file otherwise it will use default one.

Info:\
https://learn.microsoft.com/en-us/archive/technet-wiki/32490.active-directory-bad-passwords-and-account-lockout

You should give PDC as your server, you can find it with;\
`nslookup -type=SRV _ldap._tcp.pdc._msdcs.DOMAIN_NAME [DNS IP]`\
or\
`dnsrecon -d DOMAIN_NAME [-ns DNS IP]`

record should look like this:
_ldap._tcp.pdc._msdcs.example.local


# Examples
Install
```bash
pipx install git+https://github.com/kcancurly/smartbrute
```
Basic Usage
```bash
smartbrute --host 127.0.0.1 --domain example.local --username username --password password
```
Time Based Tries \
This coude would try 3 attempts between 18:00 and 20:00 per try
```bash
smartbrute --host 127.0.0.1 --domain example.local --username username --password password --time-based-tries "3:18:00-20:00"
```