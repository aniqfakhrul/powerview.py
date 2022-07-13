# PywerView [beta]

## Disclaimer
This repository has nothing related to the existing [PywerView](https://github.com/the-useless-one/pywerview) project that is already publicly available. This is only meant for my personal learning purpose and would like to share the efforts with everyone interested. This project will be supported by the collaborators from time to time, so don't worry.

This is still in **beta** mode as bugs are likely to occur during execution. Please submit issue if you encounter any issues with the tool.

## What is PywerView?
PywerView is an alternative for the awesome original [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) script. Most of the modules used in PowerView are available in this project ( some of the flags are changed ). 

## Interesting Features
* Embeded user session
* Mini PywerView console to make you feel like home when using PowerView in Powershell
* Auto-completer, so no more memorizing commands
* Cross-Domain interactions (might or might not work)
_Maybe more?_

## Why not just stick with the ps1 script?
As most of yall know, _PowerView.ps1_ is highly likely to get detected by Defender or AV vendors once downloaded onto the PC. An offensive tool to get detected by AV is a red flag during engagement. Maybe some of you thinking, why not just bypass AMSI and import the script undetected? Well, some of the big companies normally have EDR installed on most endpoints and EDRs are normally hook amsi patching and also most likely would get detected during AMSI patching. So, PywerView FTW!

## Usage
_Note that some of the kerberos functions are still not functioning well just yet_
```
python3 pywerview.py range.net/lowpriv:Password123 --dc-ip 192.168.86.192 [--use-ldaps]
```
![usage](https://cdn.discordapp.com/attachments/867691675563982878/996623323196833873/Screenshot_2022-07-13_103827.png)

## Module available (so far?)
| Module | Alias | Description |
| ------ | ----- | ---- |
|Get-Domain|Get-NetDomain||
| Get-DomainController | Get-NetDomainController ||
| Get-DomainDNSZone    |                         ||
| Get-DomainCA         | Get-NetCA               ||
|Get-DomainGPO|Get-NetGPO||
|Get-DomainGPOLocalGroup|Get-GPOLocalGroup||
|Get-DomainOU|Get-NetOU||
|Get-DomainTrust|Get-NetTrust||
|Get-DomainUser|Get-NetUser||
|Get-NamedPipes|||
|Get-Shares|Get-NetShares||
|Get-DomainComputer|Get-NetComputer||
|Get-DomainObject|Get-ADObject||
|Get-DomainObectAcl|Get-ObjectAcl||
|Add-DomainObectAcl|Add-ObjectAcl|Supported rights so far are All, DCsync, RBCD, ShadowCred, WriteMembers|
|Remove-DomainObjectAcl|Remove-ObjectAcl||
|Add-DomainGroupMember|Add-GroupMember||
|Remove-DomainGroupmember|Remove-GroupMember||
|Add-DomainComputer|Add-ADComputer||
|Remove-DomainComputer|Remove-ADComputer||
|Add-DomainUser|Add-ADUser||
|Remove-DomainUser|Remove-ADUser||
|Set-DomainObject|Set-Object||
|Set-DomainUserPassword|||
|Find-LocalAdminAccess|||
|Invoke-Kerberoast|||
|ConvertFrom-SID|||

### To-Do
* Added more delegation rights to Add-ObjectAcl
  * setShadowCredentials
  * setGenericAll
  * setOwner

### Credits
* https://github.com/SecureAuthCorp/impacket
* https://github.com/CravateRouge/bloodyAD
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
* https://github.com/ShutdownRepo/impacket/
