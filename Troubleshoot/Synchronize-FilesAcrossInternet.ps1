<#
 # Author: Andrew Harris (aharri@microsoft.com; @ciberesponce)
 # Useful when needed to debug binary on Azure resource
 # Visual Studio requires files to be in same location
 # This script ensures that, where you can then use VS Remote Debugger properly
#>
param(
    #source path
    # source path
    [Parameter(Mandatory=$true)]
    [string]
    $SourcePath,

    # destination IP
    [Parameter(Mandatory=$true)]
    [string]
    $DestinationIp,

    # remote user
    [Parameter(Mandatory = $true)]
    [string]
    $remoteUser,

    # remote user domain
    [Parameter(Mandatory = $false)]
    [string]
    $remoteUserDomain,

    # remote user password
    [Parameter(Mandatory=$true)]
    [string]
    $remoteUserPass
)

$homedir = Resolve-Path $SourcePath
$destIP = $DestinationIp
$remoteUser = $remoteUser
$remoteUserDomain = $remoteUserDomain
$remoteUserPassword = $remoteUserPass

$homedirModified = $homedir.ToString() -split ':\\'
$drive = $homedirModified[0]
$netuseUri = "\\$destIP\IPC`$"

$destString = "\\$destIP\$drive`$\$($homedirModified[1])"

# ensure we use proper network cred
net use $netuseUri /user:$remoteUserDomain\$remoteUser $remoteUserPassword
# use robocopy
robocopy $homedir $destString /mir /r:1 /w:1
Write-Host "[+] Mirrored source with destination" -ForegroundColor Green
# remove network cred
net use $netuseUri /D | Out-Null
Write-Host "[+] Properly closed connection and cleared credentials for remote/target machine" -ForegroundColor Green