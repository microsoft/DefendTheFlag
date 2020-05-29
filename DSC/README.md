# What's the resources for?

ARM does a lot of heavy lifting, but DSC does even more.  In these DSC configurations, [Choco](https://chocolatey.org/) is also leveraged on all the VMs.

## ContosoDC

ContosoDC is the Domain Controller.  It's default Forest is 'Contoso.Azure'.  It also creates users, including:

| Username | Role | Purpose |
|----------|------|---------|
| SamiraA  | Domain Admin | Manages the domain |
| RonHD    | Helpdesk | Manages endpoints, but not Domain Controller |
| JeffL    | Unprivileged domain user, has admin access to VictimPC | User which is compromised, has admin access on own workstation to mimic local escalation |
| LisaV    | Unprivileged domain user, high impact user | Has access to highly confidential data | 
| JulianI    | Unprivileged domain user, high impact user | MCAS Demo account |
| MeganB    | Unprivileged domain user, high impact user | MCAS Demo account |

## VictimPC

This is where majority of attack tools are staged. VictimPC is where the adversary starts.

Note that these attack tools are for research purposes, and really aren't "malicious" but can be used maliciously based on *intent*.  Those tools include:
* Mimikatz (thanks [Benjamin Delpy](https://twitter.com/gentilkiwi]))
* PowerSploit (thanks [Will](https://twitter.com/HarmJ0y))
* Kekeo (thanks [Benjamin Delpy](https://twitter.com/gentilkiwi))

>**Note**
>
>[JoeWare's NetSess.exe](http://www.joeware.net/freetools/tools/netsess/index.htm) explicitly prevents us from including this automatically in the build.  You can however, add this yourself by grabbing it from their site.

## AdminPC

This is where SamiraA operates from.  This mimics a Privileged Admin Workstation (PAW).  It also shows that these workstations also have to be managed, which is why RonHD is also an administrator of this machine.

## Ubuntu-Katoolin

Ubuntu-Katoolin is a preconfigured Katoolin Ubuntu workstation to simulate attacks within the demo enviroment

| Username | Role | Purpose |
|----------|------|---------|
| Cookies  | (adm),(dialout),(cdrom),(floppy),(sudo),(audio),(dip),(video),(plugdev),(netdev),(lxd) | Root admin for Ubuntu Kali box |

Kail-tools has been configured to the Ubuntu sources.list

Build configuration file has been stored within the '/' directory named Runcmd.txt from the Runcmd Cloud-init configuration from 'ProvisionKatoolin.Yaml'


Non-attack tools preinstalled:
* [Unzip & Zip](http://manpages.ubuntu.com/manpages/xenial/en/man1/unzip.1.html)
* [rdate](http://manpages.ubuntu.com/manpages/xenial/man8/rdate.8.html)
* [python-pyftpdlib](https://pypi.org/project/pyftpdlib/)


Cloned the DefendTheFlag repository into /usr/bin/DefendTheFlag

Extracted and Unzipped Attack/Bash scripts into Cookies user directory '~'

Note that these attack tools are for research purposes, and really aren't "malicious" but can be used maliciously based on *intent*.  Those tools include:
* [Hydra](https://github.com/vanhauser-thc/thc-hydra)
* [Arimtage and Metaspolit from Kalitools](https://tools.kali.org/exploitation-tools/armitage)
* [python3-impacket](https://github.com/SecureAuthCorp/impacket)

>**Note**
>
> Future updates of DefendTheFlag build with have automatic attacks for other boxes within the DTF build through automation of scheduled tasks




## Client01

Has data on the machine which can be seen as confidential, including credit card information and social security data.