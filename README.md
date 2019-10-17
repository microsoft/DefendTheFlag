# Defend the Flag

Want to test out Microsoft Security products (and others) but don't have the environment to thoroughly test? Want to simulate Active Directory, privileged users, to learn more about credential exposure and credential abuse? Want to learn more about attack tools so you can become a better computer and network defender?

This project aims at lowering the friction to get started.  By leveraging Azure Resource Manager (ARM; `azuredeploy.json` and `Nested`) and Desired State Configuration (DSC; `DSC`), we can build this entire environment within 40 minutes--the majority of that time is performing a DC promo.  

This project also includes code to then take the VMs and snapshot their disks (`Stage`).  This allows you to later have deployment tasks on those disks which take roughly 2 minutes.

> DISCLAIMER
> These VMs should not be placed in production environments or used in production workloads. The settings of the VMs have antivirus purposefully disabled, updates disabled (after provisioning), and attack tools stagged.

## Contents

| File/folder       | Description                                                                       |
|-------------------|-----------------------------------------------------------------------------------|
| `Downloads`       | Staged code.                                                                      |
| `Nested`          | Nested ARM scripts for ARM deployment. Extends azuredeploy.json                   |
| `Stage`           | Scripts to help *snapshot* resources. Convert them to images for easy deployment  |
| `Troubleshoot`    | Helper scripts to help troubleshoot and build-out ARM and DSC environment         |
| `DSC`             | Desired State Configuration which configure the resources after ARM provisioning  |
| `CHANGELOG.md`    | List of changes to the sample.                                                    |

## Setup

Primer for PowerShell Az cmdlets: [here](https://docs.microsoft.com/en-us/powershell/azure/get-started-azureps?view=azps-2.6.0)

## About the environment

This creates VMs, one of those VMs being a Domain Controller which hydrates users in an AD environment.  Those users are also configured appropriately on the respective VMs to simulate management and administrative activities.

For more information refer to ```DSC``` [folder](./Dsc/README.md).

### Phase 0 (build from absolute scratch)
To build from scratch (**Phase 0**):

1. ```New-AzResourceGroup -Name <<resource-group-name>>```
2. ```New-AzResourceGroupDeployment -ResourceGroupName <<resource-group-name>> -TemplateFile .\azuredeploy.json```

The first command creates the resource group (in your respective Tenant).  The second line hydrates the new resource group with the provided ARM tempalte file.  The ```azuredeploy.json``` wraps in the Desired State Configuration policys to build out the Domain Controller, VictimPC, AdminPC and Client01.

You can make modifications to these VMs, but again, we recommend any change is made at the ARM and DSC level.

If you wish to remove the DSC from a resource, use the ```Remove-AzVmExtension``` command. Make the desired configurations to the DSC, re-compile the DSC (```Publish-AzVmDscConfiguratoin```) and repeat the above steps, although you do not need to re-create another resource-group.  You can target the same one and Azure is smart enough to know what ARM to apply, and same with DSC, thanks to them being idempotent.

Once you have what you want, you can use the scripts in ```Stage``` folder to help capture the VMs and move them into Azure Storage Containers.  This allows us to then deploy these VMs in minutes vs seconds.

### Phase 1: Stagging Changes

```Stage``` has what you need.  Use ```New-BackupVmsToDisk.ps1```, point to the right resource group, and the disks will be snapshotted to the resource-group.  Then, ```New-MoveDisksToStorageAccountContainer.ps1``` will take those snapshots and move them into the respective Azure Storage Account container.

Once this is done, you can do Phase 2.

### Phase 2: Deploying from Stagged Chnages

Like before, but with different parameters, we can deploy VMs.

1. ```New-AzResourceGroup -Name <<other-resource-group-name>>```
2. ```New-AzResourceGroupDeployment -ResourceGroupName <<other-resource-group-name>> -Templatefile .\template.json```

Note that ```template.json``` will need to be updated so it points to the right location of the VMs earlier captured.  This can be done very quickly once you realize the variables use specific names (i.e. ```DcVhdUri``` is the Domain Controller's VHD URI).  Also note the other changes that can be made in the ```template.json``` including the VMs names.

The most critical part of this is knowing the Domain Controller becomes the vNet's DNS server, which can only happen *after* the DC VM exists.  For this reason, we have a nested ARM template, similar to what we do in Phase 0.  Without this, VMs would not always be able to resolve each other consistently and a race-condition would exist between the vNet DNS settings taking effect before the other VMs are built.

### Access your VMs

Regardless of if your in Phase 0 or Phase 2, you eventually will want to access your VMs.  You can of course do this from the Azure Portal, but we also created a quick script, ```Get-VmsInfo.ps1```.  This will tell you the VMs IPs.  You can then ```mstsc /v:<<ip>>``` or, ```ssh <<ip>>``` to quickly RDP into that machine, depending on the VM type and its authentication service.

## Skip straight to Phase 2

Want to skip Phase 0?  Feel free to grab our VHDs from an open Azure Storage account.

* ContosoDC: https://publicdefendtheflag.blob.core.windows.net/public/ContosoDcd.vhd
* VictimPC: https://publicdefendtheflag.blob.core.windows.net/public/VictimPcd.vhd
* AdminPC: https://publicdefendtheflag.blob.core.windows.net/public/AdminPcd.vhd
* Client01: https://publicdefendtheflag.blob.core.windows.net/public/Client01d.vhd
* Ubuntu-Katoolin: https://publicdefendtheflag.blob.core.windows.net/public/Ubuntu-Katoolind.vhd

> NOTE:
> Ubuntu-Katoolin will leverage Ubuntu since it supports ```cloud-init``` and the [Katoolin](https://github.com/LionSec/katoolin) project.  No work has been done to automate on top of this **yet**, however, scripts exist in the ```Downloads``` > ```Katoolin``` folder.  Until automation exists, grabbing the VHD for Ubuntu-Katoolin adds very little.  The scripts are more important here as grabbing the necessary files is fairly easy with the right distro.

Don't want to download them?  See guidance on ```Phase 2```; those commands automatically pull from these public Azure Storage Containers; total deployment time is usually ~2 minutes.

## Linked content

Once you have your lab, that is just when the fun *begins*.  Now its time to actually use the lab to learn, grow and practice.

Here is some content that builds on top of these labs:

| Product       | Title/Link   | Description                                                                                           |
|---------------|--------------|-------------------------------------------------------------------------------------------------------|
| Azure ATP     | [Attack Simulation Playbook](https://aka.ms/aatpsaplaybook) | Learn about the various attacks      |
| Azure ATP     | [Ciberesponce: Kali Pass the Ticket](https://ciberesponce.com/2019/04/16/leverage-windows-tickets-in-kali-linux/)| Learn to use harvested tickets from Windows, on Kali |


## About the author

The maintainer is a Principal PM/Architect at Microsoft for the Cloud and Artificial Intelligence (C+AI) Security team.  You can find more of his work and thoughts at [Ciberesponce.com](https://ciberesponce.com).

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## ToDo
* [AATP] Replace NetSess.exe with [Nmap NSE script](https://nmap.org/nsedoc/scripts/smb-enum-sessions.html)
* [AIP] Add back AIP components
* [AATP] Merge VictimPC from previous build
* [All] Fix issue with security settings
* [AIP] Convert AdminPC to regular disk size
* [AIP] Copy AdminPC, creating AdminPc2