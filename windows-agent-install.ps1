$globalip = ""
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.4.5-1.msi -OutFile ${env:tmp}\wazuh-agent.msi
Start-Sleep -s 10
msiexec.exe /i ${env:tmp}\wazuh-agent.msi /q WAZUH_MANAGER=$globalip WAZUH_REGISTRATION_SERVER=$globalip WAZUH_REGISTRATION_PASSWORD='' WAZUH_AGENT_GROUP='Windows' 
$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (Test-Path -Path $sysinternals_folder) {
    write-host ('Sysinternals folder already exists')
} else {
  $OutPath = $env:TMP
  $output = $sysinternals_zip
  New-Item -Path "C:\Program Files" -Name "sysinternals" -ItemType "directory"
  $X = 0
  do {
    Write-Output "Waiting for network"
    Start-Sleep -s 5
    $X += 1
  } until(($connectreult = Test-NetConnection $sysinternals_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

  if ($connectreult.TcpTestSucceeded -eq $true){
    Try
    {
    write-host ('Downloading and copying Sysinternals Tools to C:\Program Files\sysinternals...')
    Invoke-WebRequest -Uri $sysinternals_downloadlink -OutFile $OutPath\$output
    Expand-Archive -path $OutPath\$output -destinationpath $sysinternals_folder
    Start-Sleep -s 10
    Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile $OutPath\$sysmonconfig_file
    $serviceName = 'Sysmon64'
    If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('Sysmon Is Already Installed')
    } else {
    Invoke-Command {reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Invoke-Command {reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-i", "$OutPath\$sysmonconfig_file")
    }
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error -Message "$ErrorMessage $FailedItem"
        exit 1
    }
    Finally
    {
        Remove-Item -Path $OutPath\$output
    }

  } else {
      Write-Output "Unable to connect to Sysinternals Repo"
  }
}
# wait for 4 minutes
Start-Sleep -s 30
# we now have to generate an authorization key
$wazuhauthpath = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
Start-Process -FilePath $wazuhauthpath -Argumentlist @("-m", "$globalip")
$wazuhpath = "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
Start-Process -FilePath $wazuhpath
Start-Service WazuhSvc

# PART 1 Create folder C:\Program Files\Fortifier with powershell
$folderPath = "C:\Program Files\Fortifier"
if (!(Test-Path $folderPath)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Download the specified version of Git for Windows
$downloadLink = "https://github.com/git-for-windows/git/releases/download/v2.40.0.windows.1/Git-2.40.0-64-bit.exe"
$gitInstaller = "git-latest-windows.exe"
Invoke-WebRequest -Uri $downloadLink -OutFile ${env:tmp}\$gitInstaller

# wait for a few seconds
Start-Sleep -s 30

# Install Git
Start-Process -FilePath ${env:tmp}\$gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART", "/LOG=git_install.log" -NoNewWindow -Wait

# Remove the installer
Remove-Item -Path ${env:tmp}\$gitInstaller

# Add Git to the system PATH
$gitBinPath = "${env:ProgramFiles}\Git\cmd"
$env:Path += ";$gitBinPath"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";$gitBinPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")

## download git related files
$chainsawUrl = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.7.2/chainsaw_x86_64-pc-windows-msvc.zip"
$chainsawZip = "chainsaw-windows.zip"
Invoke-WebRequest -Uri $chainsawUrl -OutFile $chainsawZip

$Fail2BanUrl = "https://github.com/Aldaviva/Fail2Ban4Win/releases/download/1.2.0/Fail2Ban4Win.zip"
$Fail2BanZip = "Fail2Ban.zip"
Invoke-WebRequest -Uri $Fail2BanUrl -OutFile $Fail2BanZip

# extract downloaded zips
$chainsawFolderPath = $folderPath
Expand-Archive -Path $chainsawZip -DestinationPath $chainsawFolderPath
Remove-Item -Path $chainsawZip

$fail2banfolderpath = $folderPath 
Expand-Archive -Path $Fail2BanZip -DestinationPath $folderPath
Remove-Item -Path $Fail2BanZip

# Install fail2banwin
& 'C:\Program Files\Fortifier\Install Service.ps1'

# Start and automate fail2banwin
Set-Service -Name "Fail2Ban4Win" -StartupType Automatic  
Start-Service Fail2Ban4Win

# Download the SIGMA repository
$repoUrl = "https://github.com/SigmaHQ/sigma.git"
$destinationFolder = "C:\Program Files\Fortifier\chainsaw\sigma"
git clone $repoUrl $destinationFolder

#4: add script with content "test" to C:\Program Files (x86)\ossec-agent\active-response\bin\chainsaw.ps1
$fullscript = "
##########
# Chainsaw will be run against all event logs found in the default location
# Output converted to JSON and appended to active-responses.log
##########

##########
# Chainsaw Version: v2.5.0
##########

`$ErrorActionPreference = ""SilentlyContinue""

# Clone or pull Sigma repo
`$repo_path = ""C:\Program Files\Fortifier\chainsaw\sigma""
if (!(test-path `$repo_path)) {
    New-Item -ItemType Directory -Force -Path `$repo_path
    `$env:PATH += "";C:\Program Files\Git\bin""
    git clone https://github.com/SigmaHQ/sigma.git `$repo_path
} else {
    `$env:PATH += "";C:\Program Files\Git\bin""
    git -C `$repo_path pull
}

# Analyse events recorded in last 5 Minutes. Convert Start Date to Timestamp
`$start_date = (Get-Date).AddMinutes(-5).ToUniversalTime()  
`$from = Get-Date -Date `$start_date -UFormat '+%Y-%m-%dT%H:%M:%S'

# Create Chainsaw Output Folder if it doesn't exist
`$chainsaw_output = ""`$env:TMP\chainsaw_output""
If(!(test-path `$chainsaw_output)) {
    New-Item -ItemType Directory -Force -Path `$chainsaw_output
}

# Windows Sigma Path
`$windows_path = ""C:\Program Files\Fortifier\chainsaw\sigma\rules\windows""

# Run Chainsaw and store JSONs in TMP folder
& 'C:\Program Files\Fortifier\chainsaw\chainsaw.exe' hunt C:\Windows\System32\winevt -s `$windows_path --mapping 'C:\Program Files\Fortifier\chainsaw\mappings\sigma-event-logs-all.yml' --from `$from --output `$env:TMP\chainsaw_output\results.json --json --level high --level critical --status stable
--
# Convert JSON to new line entry for every 'group'
function Convert-JsonToNewLine(`$json) {
    foreach(`$document in `$json) {
        `$document.document | ConvertTo-Json -Compress -Depth 99 | foreach-object {
            [pscustomobject]@{
                group = `$document.group
                kind = `$document.kind
                document = `$_
                event = `$document.document.data.Event.EventData
                path = `$document.document.path
                system = `$document.document.data.Event.System
                name = `$document.name
                timestamp = `$document.timestamp
                authors = `$document.authors
                level = `$document.level
                source = `$document.source
                status = `$document.status
                falsepositives = `$document.falsepositives
                id = `$document.id
                logsource = `$document.logsource
                references = `$document.references
                tags = `$document.tags
            } | ConvertTo-Json -Compress
        }
    }
}

# Define the file path
`$file = ""C:\Program Files (x86)\ossec-agent\active-response\active-responses.log""

# Convert JSONs to new line entry and append to active-responses.log
Get-ChildItem `$env:TMP\chainsaw_output -Filter *.json | Foreach-Object {
    `$Chainsaw_Array = Get-Content `$_.FullName | ConvertFrom-Json
    Convert-JsonToNewLine `$Chainsaw_Array | Out-File -Append -Encoding ascii `$file
}

# Remove TMP JSON Folder
rm -r `$env:TMP\chainsaw_output

# Output status if Sigma rules were updated
if (`$LASTEXITCODE -eq 0) {
    `$status_payload = @{
        group = 'Sigma'
        status = 'success'
        message = 'Sigma rules were updated successfully.'
    } | ConvertTo-Json -Compress
    Write-Output `$status_payload

    # Append the payload to the log file
    `$status_payload | Out-File -Append -Encoding ascii `$file
}
else {
    `$error_payload = @{
        group = 'Sigma'
        status = 'failure'
        message = 'Failed to update Sigma rules.'
    } | ConvertTo-Json -Compress
    Write-Output `$error_payload

    # Append the payload to the log file
    `$error_payload | Out-File -Append -Encoding ascii `$file
}
"


$ossecPath = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$chainsawPs1 = Join-Path $ossecPath "chainsaw.ps1"
if (!(Test-Path $ossecPath)) {
New-Item -ItemType Directory -Path $ossecPath | Out-Null
}
Set-Content -Path $chainsawPs1 -Value $fullscript

# Now set remote scans to true
$path = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"  
  
$content = Get-Content $path  
$content += "wazuh_command.remote_commands=1"  
  
Set-Content $path $content

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

# STEP 4.6: Windows feature/antivirus based hardening

Set-MpPreference -AllowSwitchToAsyncInspection $True

#Enable Defender signatures for Potentially Unwanted Applications (PUA)
Set-MpPreference -PUAProtection enable

#https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=win10-ps
#Reduce Defender CPU Fingerprint 
#Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50%.
Set-MpPreference -ScanAvgCPULoadFactor 35

#Signature Update Interval to every 4 hours.
Set-MpPreference -SignatureUpdateInterval 4

#force update new signatures before each scan starts
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1

# Enable Cloud functionality of Windows Defender
powershell.exe Set-MpPreference -MAPSReporting 2
powershell.exe Set-MpPreference -SubmitSamplesConsent 3
# Levels Default,Moderate,High,HighPlus, or ZeroTolerance
Set-MpPreference -CloudBlockLevel ZeroTolerance
Set-MpPreference -CloudExtendedTimeout 50

# Enable Defender exploit system-wide protection
# The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
# powershell.exe Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

Set-MpPreference -EnableNetworkProtection Enabled 

# Configure whether real-time protection and Security Intelligence Updates are enabled during OOBE
Set-MpPreference -OobeEnableRtpAndSigUpdate $True

# Enable Intel Threat Detection Technology
Set-MpPreference -IntelTDTEnabled $True

# Add OneDrive folders of all user accounts to the Controlled Folder Access for Ransomware Protection
Get-ChildItem 'C:\Users\*\OneDrive' | ForEach-Object { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

# Enable Mandatory ASLR Exploit Protection system-wide
Set-ProcessMitigation -System -Enable ForceRelocateImages

# Mitigations for specific processes

# Download Process Mitigations CSV file from GitHub or Azure DevOps
try {
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/ProcessMitigations.csv' -OutFile '.\ProcessMitigations.csv' -ErrorAction Stop                
}
catch {
    Write-Host 'Using Azure DevOps...' -ForegroundColor Yellow
    Invoke-WebRequest -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/ProcessMitigations.csv' -OutFile '.\ProcessMitigations.csv' -ErrorAction Stop
}

# Apply Process Mitigations
[System.Object[]]$ProcessMitigations = Import-Csv 'ProcessMitigations.csv' -Delimiter ','

# Group the data by ProgramName
[System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object ProgramName

# Loop through each group
foreach ($Group in $GroupedMitigations) {
    # Get the program name
    $ProgramName = $Group.Name
                    
    # Get the list of mitigations to enable
    $EnableMitigations = $Group.Group | Where-Object { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation
                    
    # Get the list of mitigations to disable
    $DisableMitigations = $Group.Group | Where-Object { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation
                    
    # Call the Set-ProcessMitigation cmdlet with the lists of mitigations
    if ($null -ne $EnableMitigations) {
        if ($null -ne $DisableMitigations) {
            Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations -Disable $DisableMitigations
        }
        else {
            Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations
        }
    }
    elseif ($null -ne $DisableMitigations) {
        Set-ProcessMitigation -Name $ProgramName -Disable $DisableMitigations
    }
    else {
        Write-Warning "No mitigations to enable or disable for $ProgramName"
    }
}

# Create scheduled task for fast weekly Microsoft recommended driver block list update

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

if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
    Edit-Registry -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD' -Action 'AddOrModify'
}
elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'On') {
    Write-Host "Smart App Control is already turned on, skipping...`n"
}
elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'Off') {
    Write-Host "Smart App Control is turned off. Can't use registry to force enable it.`n"
}

# This PowerShell script disables the display of the last signed-in user information  
  
# Check if the script is running with administrative privileges  
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {  
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red  
    Exit  
}  
  
# Set the registry key path and value name  
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"  
$valueName = "DontDisplayLastUserName"  
  
# Check if the registry key exists and create it if it doesn't  
if (-not (Test-Path $registryPath)) {  
    New-Item -Path $registryPath -Force | Out-Null  
}  
  
# Set the value data to disable the display of the last signed-in user information  
Set-ItemProperty -Path $registryPath -Name $valueName -Value 1 -Type DWORD -Force  
  
Write-Host "The display of the last signed-in user information has been disabled." -ForegroundColor Green  


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


#TODO 1: require secure logins and passwords
#TODO 2: ??

# STEP 5: install the latest release of hardeningkitty
Function InstallHardeningKitty() {
    $Version = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).Name
    $HardeningKittyLatestVersionDownloadLink = ((Invoke-WebRequest "https://api.github.com/repos/0x6d69636b/windows_hardening/releases/latest" -UseBasicParsing) | ConvertFrom-Json).zipball_url
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest $HardeningKittyLatestVersionDownloadLink -Out HardeningKitty$Version.zip
    Expand-Archive -Path ".\HardeningKitty$Version.zip" -Destination ".\HardeningKitty$Version" -Force
    $Folder = Get-ChildItem .\HardeningKitty$Version | Select-Object Name -ExpandProperty Name
    Move-Item ".\HardeningKitty$Version\$Folder\*" ".\HardeningKitty$Version\"
    Remove-Item ".\HardeningKitty$Version\$Folder\"
    New-Item -Path $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version -ItemType Directory
    Set-Location .\HardeningKitty$Version
    Copy-Item -Path .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\ -Recurse
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Import-Module "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\HardeningKitty.psm1"
}
InstallHardeningKitty

# STEP 6: Automatically harden windows endpoint

# Get the url from my github to get the hardening.csv
$URL = 'https://raw.githubusercontent.com/joostgrunwald/fortifier-siem/main/hardening.csv'  

# Download the hardening file and save it to the folder where hardeningkitty resides
Invoke-WebRequest -Uri $URL -OutFile (Join-Path -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\" -ChildPath 'hardening.csv')  
 
# Run hardeningkitty in hailmary mode to harden the Windows computer
Invoke-HardeningKitty -EmojiSupport -Mode HailMary -Log -Report -FileFindingList (Join-Path -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\" -ChildPath 'hardening.csv')

# Run hardeningkitty in hailmary mode to harden the Windows computer
#TODO: run second time with ignorebackup
Invoke-HardeningKitty -EmojiSupport -Mode HailMary -SkipRestorePoint -Log -Report -FileFindingList (Join-Path -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\" -ChildPath 'hardening.csv')

# Now also apply CIS benchmark hardening:
$URLCIS = 'https://github.com/scipag/HardeningKitty/blob/master/lists/finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv'
Invoke-WebRequest -Uri $URLCIS -OutFile (Join-Path -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\" -ChildPath 'finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv')  

# Run hardeningkitty in hailmary mode to harden the Windows computer
Invoke-HardeningKitty -EmojiSupport -SkipRestorePoint -Log -Report -FileFindingList (Join-Path -Path "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty\$Version\lists\" -ChildPath 'finding_list_cis_microsoft_windows_10_enterprise_22h2_machine.csv')


# STEP 7: Fortifier/IeCeTee branding
# Define the URL of the image  
$imageUrl = "https://github.com/joostgrunwald/fortifier-siem/blob/main/fortifier.jpg?raw=true"  
  
# Define the local path to save the image  
$localImagePath = "$env:USERPROFILE\Desktop\fortifier.jpg"  
  
# Download the image from the URL  
Invoke-WebRequest -Uri $imageUrl -OutFile $localImagePath  
  
# Set the downloaded image as wallpaper  
Add-Type -TypeDefinition @"  
using System;  
using System.Runtime.InteropServices;  
  
public class Wallpaper {  
    [DllImport("user32.dll", CharSet = CharSet.Auto)]  
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);  
}  
"@  
  
$SPI_SETDESKWALLPAPER = 0x0014  
$SPI_UPDATEINIFILE = 0x01  
$SPIF_UPDATEINIFILE = 0x01  
$SPIF_SENDCHANGE = 0x02  
  
[Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $localImagePath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)  
