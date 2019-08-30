###
# Shouldn't be used until images are better handled with SAS and can be moved...
# Images are better in that they take all Disks of a Machine...
# Author: aharri@microsoft.com
##

param(
    [Parameter(Mandatory=$false)]
    [string]
    $ResourceGroupName = 'cxe-lab-test',

    # location for image
    [Parameter(Mandatory=$false)]
    [string]
    $Location = 'East US2',

    # DestingationResourceGroup
    [Parameter(Mandatory=$false)]
    [string]
    $DestinationResourceGroupName = 'cxe-lab-images'
)

$vms = Get-AzVm -ResourceGroupName $ResourceGroupName

Write-Host "[+] Starting to backup Images for $($vms.Count) VMs..." -ForegroundColor Yellow

foreach ($vm in $vms){
    Write-Host "`t[ ] Backing up $($vm.Name)" -ForegroundColor Cyan
    $diskId = $vm.StorageProfile.OsDisk.ManagedDisk.Id # get only the OS disk; no other drives are included

    $imageConfig = New-AzImageConfig -Location $Location 
    $imageConfig = Set-AzImageOsDisk -Image $imageConfig `
        -OsType $vm.StorageProfile.OsDisk.OsType.ToString() `
        -ManagedDiskId $diskId        

    New-AzImage -ImageName "$($vm.Name)image" -ResourceGroupName andrew-images -Image $imageConfig
    Write-Host "`t[+] $($vm.Name):`tImage Backup complete"
}
Write-Host "[+] Captured Images Job Complete."
