Use POST for `/api/ldap/rebind`, `/api/ldap/close`, and `/api/clear-cache`. These operations take no body and change the shared PowerView session. Browser clients must send POST requests from the same origin as the web interface.

[API documentation](https://github.com/aniqfakhrul/powerview.py/wiki/API-Documentation)
