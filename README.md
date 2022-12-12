# PowerView.py [beta]

## Disclaimer
This repository has nothing related to the existing [PowerView.py](https://github.com/the-useless-one/pywerview) project that is already publicly available. This is only meant for my personal learning purpose and would like to share the efforts with everyone interested. This project will be supported by the collaborators from time to time, so don't worry.

This is still in **beta** mode as bugs are likely to occur during execution. Please submit issue if you encounter any issues with the tool.

## What is PowerView.py?
PowerView.py is an alternative for the awesome original [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script. Most of the modules used in PowerView are available in this project ( some of the flags are changed ). 

## Interesting Features
* Embeded user session
* Mini PowerView.py console to make you feel like home when using PowerView in Powershell
* Auto-completer, so no more memorizing commands
* Cross-Domain interactions (might or might not work)
_Maybe more?_

## Why not just stick with the ps1 script?
As most of yall know, _PowerView.ps1_ is highly likely to get detected by Defender or AV vendors once downloaded onto the PC. An offensive tool to get detected by AV is a red flag during engagement. Maybe some of you thinking, why not just bypass AMSI and import the script undetected? Well, some of the big companies normally have EDR installed on most endpoints and EDRs are normally hook amsi patching and also most likely would get detected during AMSI patching. So, PowerView.py FTW!

## Installation
```
python3 setup.py install
```

## Usage
_Note that some of the kerberos functions are still not functioning well just yet_
* Init connection
```
powerview.py range.net/lowpriv:Password123 --dc-ip 192.168.86.192 [-h]
```
![usage](https://cdn.discordapp.com/attachments/867691675563982878/996623323196833873/Screenshot_2022-07-13_103827.png)

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
|Get-Domain|Get-NetDomain||
| Get-DomainController | Get-NetDomainController ||
| Get-DomainDNSZone    |                         ||
| Get-DomainDNSRecord    |                         ||
| Get-DomainCA         | Get-NetCA               ||
| Get-DomainCATemplate         | Get-NetCATemplate               ||
|Get-DomainGPO|Get-NetGPO||
|Get-DomainGPOLocalGroup|Get-GPOLocalGroup||
|Get-DomainOU|Get-NetOU||
|Get-DomainTrust|Get-NetTrust||
|Get-DomainUser|Get-NetUser||
|Get-DomainGroup|Get-NetGroup||
|Get-DomainGroupMember|Get-NetGroupMember||
|Get-NamedPipes|||
|Get-Shares|Get-NetShares||
|Get-DomainComputer|Get-NetComputer||
|Get-DomainObject|Get-ADObject||
|Get-DomainObjectOwner|Get-ObjectOwner||
|Get-DomainObjectAcl|Get-ObjectAcl||
|Add-DomainObjectAcl|Add-ObjectAcl|Supported rights so far are All, DCsync, RBCD, ShadowCred, WriteMembers|
|Remove-DomainObjectAcl|Remove-ObjectAcl||
|Add-DomainGroupMember|Add-GroupMember||
|Remove-DomainGroupmember|Remove-GroupMember||
|Add-DomainComputer|Add-ADComputer||
|Remove-DomainComputer|Remove-ADComputer||
|Add-DomainUser|Add-ADUser||
|Remove-DomainUser|Remove-ADUser||
|Set-DomainObject|Set-Object||
|Set-DomainUserPassword|||
|Set-DomainCATemplate|Set-CATemplate||
|Set-DomainDNSRecord|||
|Set-DomainObjectOwner|Set-ObjectOwner||
|Find-LocalAdminAccess|||
|Invoke-Kerberoast|||
|ConvertFrom-SID|||

### To-Do
* Add a wiki?

### Credits
* https://github.com/SecureAuthCorp/impacket
* https://github.com/CravateRouge/bloodyAD
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* https://github.com/ShutdownRepo/impacket/
* https://github.com/the-useless-one/pywerview
* https://github.com/dirkjanm/ldapdomaindump
