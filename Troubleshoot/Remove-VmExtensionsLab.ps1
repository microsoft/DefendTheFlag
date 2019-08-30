param(
    # ResourceGroupName
    [Parameter(Mandatory = $false)]
    [string]
    $resourceGroup = 'cxe-lab-test'
)
Write-Host "[!] Remove VM Extensions from the `'$resourceGroup`' RG" -ForegroundColor Cyan
#array showing VMName, DSC name
$vmData = @(
    ('ContosoDc', 'DcPromoDsc'),
    ('AdminPc', 'AdminPcDsc'),
    ('VictimPc', 'VictimDsc'),
    ('Client01', 'SetupMcasClient')
)
foreach ($vmSet in $vmData) {
    Remove-AzVMExtension -ResourceGroupName $resourceGroup -VMName $vmset[0] -Name $vmSet[1] -Force
}