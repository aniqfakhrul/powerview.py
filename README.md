# PowerView.py

## Disclaimer
This repository has nothing related to the existing [PowerView.py](https://github.com/the-useless-one/pywerview) project that is already publicly available. This is only meant for my personal learning purpose and would like to share the efforts with everyone interested. This project will be supported by the collaborators from time to time, so don't worry.

## What is PowerView.py?
PowerView.py is an alternative for the awesome original [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script. Most of the modules used in PowerView are available in this project ( some of the flags are changed ). There are also some major improvements to the features and functionality since we added ADCS enumeration features and some other great features_(more below)_.

We are not developers, bugs and errors are very likely to happen during execution. Please submit issue if you encounter any issues with the tool.

## Interesting Features
* Embeded user session
* Binding with multiple protocols (ldap, ldaps, gc, gc-ssl), trial and error approach. SSL connection is prioritized.
* Mini Powerview.py console to make you feel like home when using PowerView in Powershell
* Auto-completer, so no more memorizing commands
* Cross-Domain interactions (might or might not work)
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

## Usage
_Note that some of the kerberos functions are still not functioning well just yet but it still do most of the works._
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

## Module available (so far?)
| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-Domain|Get-NetDomain|Query for domain information|
| Get-DomainController | Get-NetDomainController | Query for available domain controllers |
| Get-DomainDNSZone    |                         | Query for available DNS zones in the domain |
| Get-DomainDNSRecord    |                         | Query for available records. It will recurse all DNS zones if doesn't specify -ZoneName |
| Get-DomainSCCM         | Get-SCCM               | Query for SCCM |
| Get-DomainCA         | Get-NetCA               | Query for Certificate Authority(CA) |
| Get-DomainCATemplate         | Get-NetCATemplate               | Query for available CA templates. Supports filtering for vulnerable template |
|Get-DomainGPO|Get-NetGPO| Query for domain group policy objects |
|Get-DomainGPOLocalGroup|Get-GPOLocalGroup||
|Get-DomainOU|Get-NetOU||
|Get-DomainTrust|Get-NetTrust||
|Get-DomainUser|Get-NetUser||
|Get-DomainGroup|Get-NetGroup||
|Get-DomainGroupMember|Get-NetGroupMember||
|Get-NamedPipes|||
|Get-NetSession|||
|Get-NetShare|||
|Get-DomainComputer|Get-NetComputer||
|Get-DomainObject|Get-ADObject||
|Get-DomainObjectOwner|Get-ObjectOwner||
|Get-DomainObjectAcl|Get-ObjectAcl||
|Add-DomainOU|Add-OU||
|Remove-DomainOU|Remove-OU||
|Add-DomainObjectAcl|Add-ObjectAcl|Supported rights so far are All, DCsync, RBCD, ShadowCred, WriteMembers|
|Remove-DomainObjectAcl|Remove-ObjectAcl||
|Remove-DomainObject|Remove-Object||
|Add-DomainGroupMember|Add-GroupMember||
|Remove-DomainGroupmember|Remove-GroupMember||
|Add-DomainComputer|Add-ADComputer||
|Remove-DomainComputer|Remove-ADComputer||
|Add-DomainUser|Add-ADUser||
|Remove-DomainUser|Remove-ADUser||
|Set-DomainObject|Set-Object||
|Set-DomainObjectDN|Set-ObjectDN| Modify object's distinguishedName attribute as well as changing OU|
|Set-DomainUserPassword|||
|Set-DomainCATemplate|Set-CATemplate||
|Set-DomainDNSRecord|||
|Set-DomainObjectOwner|Set-ObjectOwner||
|Find-LocalAdminAccess|||
|Invoke-Kerberoast|||
|New-GPLink|||
|ConvertFrom-SID|||

### To-Do
* Add --certificate flag to support ldap bind with certificate
* Add logging function to track and monitor what have been run.
* Stores query results to a database for offline interaction.

### Credits
* https://github.com/SecureAuthCorp/impacket
* https://github.com/CravateRouge/bloodyAD
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* https://github.com/ShutdownRepo/impacket/
* https://github.com/the-useless-one/pywerview
* https://github.com/dirkjanm/ldapdomaindump
