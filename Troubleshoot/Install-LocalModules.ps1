#
# Push modules locally
#
# eventually another project should be used to move these to official projects
# TODO: move these to formal gallery--including commit changes back up
#

$usrModules = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
Copy-Item -Path ".\DSCResources\*" -Destination $usrModules -Recurse -Force