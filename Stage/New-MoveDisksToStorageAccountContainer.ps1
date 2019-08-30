# Move disks to proper container to shared

param(
    # resourceGroupName
    [Parameter(Mandatory=$false)]
    [string]
    $ResourceGroupName = 'cxe-lab-images',

    # StorageAccount
    [Parameter(Mandatory=$false)]
    [string]
    $StorageAccount = 'caiseclabimages',

    # Container to save Images in storage account
    [Parameter(Mandatory=$false)]
    [string]
    $AssetsContainer = 'assets',

    # StorageAccount Key
    [Parameter(Mandatory=$false)]
    [string]
    $StorageAccessKey = 'slM8i/Pgyqz63cfVlnJlV8Bq2ZoJe/mvbtBiNB4eFT2sv8P9o2L7s87tLVxjVcjicqeSoN+iPFl5BuzcIxMdPQ=='
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