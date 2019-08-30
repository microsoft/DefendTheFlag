$items = Get-ChildItem ".\DSC\*.ps1" -Exclude "PublishPs1.ps1"
Write-Host "[!] Publishing $($items.Count) as DSC Modules" -ForegroundColor Cyan
foreach ($item in $items){
    $filename = $item.Name
    $basefile = $filename.Split('.')[0]
    Publish-AzVMDscConfiguration -ConfigurationPath ".\DSC\$filename" -OutputArchivePath ".\DSC\$basefile.zip" -Force
    Write-Host "`t[ ] Completed $filename" -ForegroundColor Yellow
}
Write-Host "[+] Finished publishing all ps1 files as Dsc Modules" -ForegroundColor Green