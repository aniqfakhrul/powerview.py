# PowerView.py

## Disclaimer
This repository has nothing related to the existing [pywerview.py](https://github.com/the-useless-one/pywerview) project that is already publicly available. This is only meant for my personal learning purpose and would like to share the efforts with everyone interested. This project will be supported by the collaborators from time to time, so don't worry.

## What is PowerView.py?
PowerView.py is an alternative for the awesome original [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script. Most of the modules used in PowerView are available in this project ( some of the flags are changed ). There are also some major improvements to the features and functionality since we added ADCS enumeration features and some other great features_(more below)_.

We are not developers, bugs and errors are very likely to happen during execution. Please submit issue if you encounter any issues with the tool.

## Interesting Features
* Embeded user session
* Binding with multiple protocols (ldap, ldaps, gc, gc-ssl), trial and error approach. SSL connection is prioritized.
* Mini Powerview.py console to make you feel like home when using PowerView.ps1
* Auto-completer, so no more remembering commands
* Cross-Domain interactions (might or might not work)
* Check if current user has Domain Admin or adminCount attribute set to 1
* Table format feature mirroring the output style of PowerShell's `Format-Table`.
_Maybe more?_

## Why not just stick with the ps1 script?
1. Detections
As most of yall know, _PowerView.ps1_ is highly likely to get detected by Defender or AV vendors once downloaded onto the PC. An offensive tool to get detected by AV is a red flag during engagement. Maybe some of you thinking, why not just bypass AMSI and import the script undetected? Well, some of the big companies normally have EDR installed on most endpoints and EDRs are normally hook amsi patching and also most likely would get detected during AMSI patching. So, PowerView.py FTW!

2. Proxy with ease
Running LDAP query tools through proxies (i.e. SOCKS) is quite overwhelming since it requires a lot of stuffs needed to be installed (i.e. Proxyfier). I dont think windows can support proxychains just yet (at least not on top of my head). Since powerview.py is just a python tool, wrapping it with proxychains is definitely possible. Used it most of the time and it worked like a charm!

## Installation
```
python3 setup.py install
```

## Simple Usage
_Note that some of the kerberos functions are still not functioning well just yet but it still do most of the works. More information can be found in [Wiki](https://github.com/aniqfakhrul/powerview.py/wiki) section_
* Init connection
```
powerview range.net/lowpriv:Password123@192.168.86.192 [--dc-ip 192.168.86.192] [-k]
```
[![asciicast](https://asciinema.org/a/hR3Ejy3yK9q5qsjnEV953vG4Y.svg)](https://asciinema.org/a/hR3Ejy3yK9q5qsjnEV953vG4Y)

* Query for specific user
```
Get-DomainUser Administrator
Get-DomainUser -Identity Administrator
```

* Specify search attributes
```
Get-DomainUser -Properties samaccountname,description
```

* Filter results
```
Get-DomainUser -Where 'samaccountname [contains][in][eq] admins'
```

* Count results
```
Get-DomainUser -Count
```

* Set module
```
Set-DomainObject -Identity "adminuser" -Set 'servicePrincipalname=http/web.ws.local'
Set-DomainObject -Identity "adminuser" -Append 'servicePrincipalname=http/web.ws.local'
Set-DomainObject -Identity "adminuser" -Clear 'servicePrincipalname'
```

## Module available (so far?)

```cs
PV > 
Add-ADComputer                 Find-ForeignUser               Get-DomainOU                   Get-NetTrust                   Remove-GPLink 
Add-ADUser                     Find-LocalAdminAccess          Get-DomainObject               Get-NetUser                    Remove-GroupMember 
Add-CATemplate                 Get-ADObject                   Get-DomainObjectAcl            Get-ObjectAcl                  Remove-OU 
Add-CATemplateAcl              Get-CA                         Get-DomainObjectOwner          Get-ObjectOwner                Remove-ObjectAcl 
Add-DomainCATemplate           Get-CATemplate                 Get-DomainSCCM                 Get-SCCM                       Set-CATemplate 
Add-DomainCATemplateAcl        Get-Domain                     Get-DomainTrust                Invoke-Kerberoast              Set-DomainCATemplate 
Add-DomainComputer             Get-DomainCA                   Get-DomainUser                 New-GPLink                     Set-DomainComputerPassword 
Add-DomainDNSRecord            Get-DomainCATemplate           Get-GPOLocalGroup              Remove-ADComputer              Set-DomainDNSRecord 
Add-DomainGroupMember          Get-DomainComputer             Get-NamedPipes                 Remove-ADUser                  Set-DomainObject 
Add-DomainOU                   Get-DomainController           Get-NetComputer                Remove-CATemplate              Set-DomainObjectDN 
Add-DomainObjectAcl            Get-DomainDNSRecord            Get-NetDomain                  Remove-DomainCATemplate        Set-DomainObjectOwner 
Add-DomainUser                 Get-DomainDNSZone              Get-NetDomainController        Remove-DomainComputer          Set-DomainUserPassword 
Add-GroupMember                Get-DomainForeignGroupMember   Get-NetGPO                     Remove-DomainDNSRecord         Set-Object 
Add-OU                         Get-DomainForeignUser          Get-NetGroup                   Remove-DomainGroupMember       Set-ObjectOwner 
Add-ObjectAcl                  Get-DomainGPO                  Get-NetGroupmember             Remove-DomainOU                clear 
ConvertFrom-SID                Get-DomainGPOLocalGroup        Get-NetOU                      Remove-DomainObject            exit 
ConvertFrom-UACValue           Get-DomainGroup                Get-NetSession                 Remove-DomainObjectAcl         
Find-ForeignGroup              Get-DomainGroupMember          Get-NetShare                   Remove-DomainUser                           
```

### Domain/LDAP Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainUser|Get-NetUser|Query for all users or specific user objects in AD|
|Get-DomainComputer|Get-NetComputer|Query for all computers or specific computer objects in AD|
|Get-DomainGroup|Get-NetGroup|Query for all groups or specific group objects in AD|
|Get-DomainGroupMember|Get-NetGroupMember|Query the members for specific domain group |
|Get-DomainOU|Get-NetOU|Query for all OUs or specific OU objects in AD|
|Get-Domain|Get-NetDomain|Query for domain information|
|Get-DomainController|Get-NetDomainController|Query for available domain controllers|
|Get-DomainDNSRecord||Query for available records. It will recurse all DNS zones if doesn't specify -ZoneName|
|Get-DomainDNSZone||Query for available DNS zones in the domain|
|Get-DomainObject|Get-ADObject|Query for all or specified domain objects in AD|
|Get-DomainObjectAcl|Get-ObjectAcl|Query ACLs for specified AD object|
|Get-DomainSCCM|Get-SCCM|Query for SCCM|
|Get-DomainObjectOwner|Get-ObjectOwner|Query owner of the AD object|
|Remove-DomainDNSRecord||Remove Domain DNS Record|
|Remove-DomainComputer|Remove-ADComputer|Remove Domain Computer|
|Remove-DomainGroupMember|Remove-GroupMember|Remove member of a specific Domain Group|
|Remove-DomainOU|Remove-OU|Remove OUs or specific OU objects in AD|
|Remove-DomainObjectAcl|Remove-ObjectAcl|Remove ACLs for specified AD object|
|Remove-DomainObject|Remove-ADObject|Remove specified Domain Object|
|Remove-DomainUser|Remove-ADUser|Remove specified Domain User in AD|
|Set-DomainDNSRecord||Set Domain DNS Record|
|Set-DomainUserPassword||Set password for specified Domain User|
|Set-DomainComputerPassword||Set password for specified Domain Computer|
|Set-DomainObject|Set-ADObject|Set for specified domain objects in AD|
|Set-DomainObjectDN|Set-ADObjectDN| Modify object's distinguishedName attribute as well as changing OU|
|Set-DomainObjectOwner|Set-ObjectOwner|Set owner of the AD object|
|Add-DomainDNSRecord||Add Domain DNS Record|
|Add-DomainUser|Add-ADUser|Add new Domain User in AD|
|Add-DomainComputer|Add-ADComputer|Add new Domain Computer in AD|
|Add-DomainGroupMember|Add-GroupMember|Add new member in specified Domain Group in AD|
|Add-DomainOU|Add-OU|Add new OU objects in AD|
|Add-DomainObjectAcl|Add-ObjectAcl|Supported rights so far are All, DCsync, RBCD, ShadowCred, WriteMembers|

### GPO Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainGPO|Get-NetGPO| Query for domain group policy objects |
|Get-DomainGPOLocalGroup|Get-GPOLocalGroup|Query all GPOs in a domain that modify local group memberships through `Restricted Groups` or `Group Policy preferences`|
|New-GPLink||Create new GPO link to an OU|
|Remove-GPLink||Remove GPO link from an OU|

### Computer Enumeration Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-NetSession||Query session information for the local or a remote computer|
|Get-NetShare||Query open shares on the local or a remote computer|

### ADCS Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainCATemplate|Get-CATemplate|Query for available CA templates. Supports filtering for vulnerable template|
|Get-DomainCA|Get-CA|Query for Certificate Authority(CA)|
|Remove-DomainCATemplate|Remove-CATemplate|Remove specified Domain CA Template|
|Set-DomainCATemplate|Set-CATemplate|Modify domain object's attributes of a CA Template|
|Add-DomainCATemplate|Add-CATemplate|Add new Domain CA Template|
|Add-DomainCATemplateAcl|Add-CATemplateAcl|Add ACL to a certificate template. Supported rights so far are All, Enroll, Write|

### Domain Trust Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-DomainTrust|Get-NetTrust|Query all Domain Trusts|
|Get-DomainForeignUser|Find-ForeignUser|Query users who are in group outside of the user's domain|
|Get-DomainForeignGroupMember|Find-ForeignGroup|Query groups with users outside of group's domain and look for foreign member|

### Misc Functions

| Module | Alias | Description |
| ------ | ----- | ---- |
|ConvertFrom-SID||Convert a given security identifier (SID) to user/group name|
|ConvertFrom-UACValue||Converts a UAC int value to human readable form|
|Get-NamedPipes||List out Named Pipes for a specific computer|
|Invoke-Kerberoast||Requests kerberos ticket for a specified service principal name (SPN)|
|Find-LocalAdminAccess||Finds computer on the local domain where the current has a Local Administrator access|

### To-Do
* Add logging function to track and monitor what have been run.
* Add cache functionality to minimize network interaction.
* Support more authentication flexibility.

### Credits
* https://github.com/SecureAuthCorp/impacket
* https://github.com/CravateRouge/bloodyAD
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* https://github.com/ShutdownRepo/impacket/
* https://github.com/the-useless-one/pywerview
* https://github.com/dirkjanm/ldapdomaindump
* https://learn.microsoft.com/en-us/powershell/module/grouppolicy/new-gplink
