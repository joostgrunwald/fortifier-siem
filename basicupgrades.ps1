# STEP 4.5: Country based firewall blocking
function Block-CountryIP {
    param ([string[]]$IPList , [string]$ListName)
    # deletes previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules               
    Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue
    # converts the list which is in string into array
    [string[]]$IPList = $IPList -split '\r?\n' -ne ''
    # makes sure the list isn't empty
    if ($IPList.count -eq 0) { Write-Host "The IP list was empty, skipping $ListName" -ForegroundColor Yellow ; break }      
    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
    New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost        
}    

# block terrorist sponsoring ip ranges
Invoke-WithoutProgress {   
    $global:StateSponsorsofTerrorism = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt'
}
Block-CountryIP -IPList $StateSponsorsofTerrorism -ListName 'State Sponsors of Terrorism'

# Block OFAC sanctioned countries
Invoke-WithoutProgress {   
    $global:OFACSanctioned = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt'            
}
Block-CountryIP -IPList $OFACSanctioned -ListName 'OFAC Sanctioned Countries'

# create a scheduled task that runs every 7 days
if (-NOT (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -ErrorAction SilentlyContinue)) {        
    $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
        -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
    $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $env:USERNAME -RunLevel Highest
    # trigger
    $Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7) 
    # register the task
    Register-ScheduledTask -Action $action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update'
    # define advanced settings for the task
    $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    # add advanced settings we defined to the task
    Set-ScheduledTask -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Settings $TaskSettings 
}

# set windows update to update auto
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name AUOptions -Value 4  

# Enable Windows Sandbox
PowerShell.exe "Write-Host 'Enabling Windows Sandbox' -ForegroundColor Yellow;if((get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state -eq 'disabled'){enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -norestart}else{Write-Host 'Containers-DisposableClientVM (Windows Sandbox) is already enabled' -ForegroundColor Darkgreen}"

# Turn on Data Execution Prevention (DEP) for all applications, including 32-bit programs
bcdedit.exe /set '{current}' nx AlwaysOn      

# STEP 4.7: WinGet 
# Get the download URL of the latest winget installer from GitHub:
$API_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
$DOWNLOAD_URL = $(Invoke-RestMethod $API_URL).assets.browser_download_url |
    Where-Object {$_.EndsWith(".msixbundle")}

# Download the installer:
Invoke-WebRequest -URI $DOWNLOAD_URL -OutFile winget.msixbundle -UseBasicParsing

# Install winget:
Add-AppxPackage winget.msixbundle

# Remove the installer:
Remove-Item winget.msixbundle

# Scheduled daily winget task for third party path management
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command 'winget upgrade -r'"  
$trigger = New-ScheduledTaskTrigger -Daily -At 9am  
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd  
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest  
$task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal  
Register-ScheduledTask -TaskName "WingetUpgrade" -InputObject $task 

# STEP 4.8: Enable different attack surface reduction rules that have no or less impact but reduce threat 
#(https://blog.palantir.com/microsoft-defender-attack-surface-reduction-recommendations-a5c7d41c3cf8)
# Attack surface reduction rules are normally a paid intune service (now free!)

#Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
#:: Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
#:: Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
#:: Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
#:: Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
#:: Block lsass cred theft
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
#:: Block Office from creating executables
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled


# STEP 4.9: use 1.1.1.3 for blocking of malicious websites and porn via cloudflare dns resolving (free!)

# Get the active network adapter  
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }  
  
# Set the DNS server address for the adapter  
$dnsServers = "1.1.1.3", "1.0.0.3"  
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers  
  
# Display the updated DNS settings  
Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex | Select-Object -ExpandProperty ServerAddresses  
