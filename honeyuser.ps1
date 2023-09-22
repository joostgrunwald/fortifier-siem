# Function to generate a random Dutch name  
function Get-RandomDutchName {  
    $firstNames = @("Jan", "Jeroen", "Bram", "Pieter", "Sander", "Erik", "Niels", "Ruben", "Mark", "Stijn")  
    $lastNames = @("de Vries", "van Dijk", "Jansen", "van den Berg", "Bakker", "van der Meer", "van Leeuwen", "de Jong", "de Boer", "de Groot")  
  
    $randomFirstName = $firstNames | Get-Random  
    $randomLastName = $lastNames | Get-Random  
  
    return "$randomFirstName $randomLastName"  
}  
  
# Create a local user with a random Dutch name  
$randomDutchName = Get-RandomDutchName  
$password = ConvertTo-SecureString "Your_Password_Here" -AsPlainText -Force  
New-LocalUser -Name $randomDutchName -Password $password -FullName $randomDutchName -Description "Random Dutch user"  
  
# Create a monitoring script  
$monitoringScript = @"  
`$userFilter = "TargetUserName='$randomDutchName'"  
Register-WmiEvent -Query "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LocalAccount' AND `$userFilter" -SourceIdentifier "UserActivityMonitor" -Action {  
    Invoke-WebRequest -Uri "http://krdu2i0a2cewpqyki0phrqgck.canarytokens.com" -UseBasicParsing  
}  
"@  
  
# Save the monitoring script to a file  
$monitoringScriptPath = "$env:USERPROFILE\Documents\monitor_user_activity.ps1"  
Set-Content -Path $monitoringScriptPath -Value $monitoringScript  
  
# Register the script to run at startup  
$taskName = "MonitorUserActivity"  
$taskDescription = "Monitor user activity and perform a DNS call to the specified URL"  
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File $monitoringScriptPath"  
$trigger = New-ScheduledTaskTrigger -AtStartup  
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description $taskDescription  
