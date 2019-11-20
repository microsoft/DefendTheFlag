<#
.SYNOPSIS
    Use to publish all PS1s in the DSC folder
.EXAMPLE
    PS C:\> .\PublishPs1.ps1
    Finds all PS1s in the folder, then runs Publish-AzVMDscConfiguration on that file. Outputs the file as a .zip with same basefile name.
.OUTPUTS
    Creates a DSC ArchiveFile in the .\DSC\<file-name>.zip
#>

$items = Get-ChildItem ".\DSC\*.ps1" -Exclude "PublishPs1.ps1"
Write-Host "[!] Publishing $($items.Count) as DSC Modules" -ForegroundColor Cyan
foreach ($item in $items){
    $filename = $item.Name
    $basefile = $filename.Split('.')[0]
    Publish-AzVMDscConfiguration -ConfigurationPath ".\DSC\$filename" -OutputArchivePath ".\DSC\$basefile.zip" -Force
    Write-Host "`t[ ] Completed $filename" -ForegroundColor Yellow
}
Write-Host "[+] Finished publishing all ps1 files as Dsc Modules" -ForegroundColor Green