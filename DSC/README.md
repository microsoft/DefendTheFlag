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

## Client01

Has data on the machine which can be seen as confidential, including credit card information and social security data.