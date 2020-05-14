if ($PSVersionTable.PSEdition -ne "Desktop"){
    Exit(-1)
}
#Building PSObject of required moudles; add new modules below to automate the installation
$myObject = @(
    ('xPSDesiredStateConfiguration', '8.10.0.0'),
    ('ComputerManagementDsc', '6.5.0.0'),
    ('xActiveDirectory', '3.0.0.0'),
    ('NetworkingDsc', '7.4.0.0'),
    ('xSystemSecurity', '1.4.0.0'),
    ('cChoco', '2.4.0.0'),
    ('xPendingReboot', '0.4.0.0'))

#Going through each modules+value; installing on local user profile.
foreach($obj in $myObject) {
    $m=$obj[0]
    $v=$obj[1]
    Install-Module -Name $m -RequiredVersion $v
}
