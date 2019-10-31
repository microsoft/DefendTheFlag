# Move disks to proper container to shared

param(
    # resourceGroupName
    [Parameter(Mandatory=$false)]
    [string]
    $ResourceGroupName = 'DefendTheFlag-Public',

    # StorageAccount
    [Parameter(Mandatory=$false)]
    [string]
    $StorageAccount = 'publicdefendtheflag',

    # Container to save Images in storage account
    [Parameter(Mandatory=$false)]
    [string]
    $AssetsContainer = 'public-v1',

    # StorageAccount Key
    [Parameter(Mandatory=$false)]
    [string]
    $StorageAccessKey = 'uSVzWA7GbsHoCj4PzTNMd2B9diKdB4a2C1E0UsFLncTVcEkUBQaybaUGFcIBsjfh3/6LdizVFsNA74JUyG7kMw=='
)

Write-Host "[!] Moving to proper Storage Account/containers" -ForegroundColor Yellow
$disks = Get-AzDisk -ResourceGroupName $ResourceGroupName
$destStorageContext = New-AzStorageContext -StorageAccountName $StorageAccount -StorageAccountKey $StorageAccessKey

foreach ($disk in $disks){
    $name = ($disk.Id).Split('/') | Select-Object -last 1

    Write-Host "`t[ ] Moving $name disk to Storage Account..." -ForegroundColor Cyan
    $sas = Grant-AzDiskAccess -ResourceGroupName $ResourceGroupName `
        -DiskName $disk.Name `
        -DurationInSecond 3600 -Access Read

    Start-AzStorageBlobCopy -AbsoluteUri $sas.AccessSAS `
        -DestContainer $AssetsContainer `
        -DestContext $destStorageContext `
        -DestBlob "$name.vhd" | Out-Null
    Write-Host "`t[+] Successfully copied $name disk to Storage Account..." -ForegroundColor Green
}