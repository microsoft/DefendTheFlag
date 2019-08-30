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

To build from scratch (**Phase 0**):


## Key concepts

Provide users with more context on the tools and services used in the sample. Explain some of the code that is being used and how services interact with each other.

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
