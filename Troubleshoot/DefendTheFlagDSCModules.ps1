if ($PSVersionTable.PSEdition -ne "Desktop"){
    Exit(-1)
}

#Removing myObject variable if preconfigured
Remove-Variable myObject -ErrorAction SilentlyContinue
#Building PSObject of required moudles; add new modules below to automate the installation
$myObject = @()
$myObject += New-Object psobject -Property @{'ModuleName' = 'xPSDesiredStateConfiguration'; 'Value' = '8.10.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'ComputerManagementDsc'; 'Value' = '6.5.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'xActiveDirectory'; 'Value' = '3.0.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'NetworkingDsc'; 'Value' = '7.4.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'xSystemSecurity'; 'Value' = '1.4.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'cChoco'; 'Value' = '2.4.0.0'}
$myObject += New-Object psobject -Property @{'ModuleName' = 'xPendingReboot'; 'Value' = '0.4.0.0'}


function Update-Item {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m} | Where-Object {$_.Version -eq $v}) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module | Where-Object {$_.Name -eq $m} | Where-Object {$_.Version -eq $v}) {
            Import-Module -Name $m -RequiredVersion $v -Verbose
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m -RequiredVersion $v) {
                Install-Module -Name $m -RequiredVersion $v -Force -Verbose -Scope CurrentUser
                Import-Module -Name $m -RequiredVersion $v -Verbose
            }
            else {

                # If module is not imported, not available and not in online gallery then abort
                write-host "Module $m not imported, not available and not in online gallery, exiting."
                EXIT 1
            }
        }
    }
}

#Going through each modules+value; installing on local user profile.
foreach($Object in $myObject) {

$m=$Object.ModuleName
$v=$Object.Value

Update-Item
}
