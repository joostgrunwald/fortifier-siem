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
Start-Sleep -s 240
# we now have to generate an authorization key
$wazuhauthpath = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
Start-Process -FilePath $wazuhauthpath -Argumentlist @("-m", "$globalip")
$wazuhpath = "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
Start-Process -FilePath $wazuhpath
Start-Service WazuhSvc

# PART 1 Create folder C:\Program Files\Fortifier\chainsaw with powershell
$folderPath = "C:\Program Files\Fortifier\chainsaw"
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

## PART 2 download latest chainsaw for windows from github (git later on usable??) https://github.com/WithSecureLabs/chainsaw/releases/tag
$chainsawUrl = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.7.2/chainsaw_x86_64-pc-windows-msvc.zip"
$chainsawZip = "chainsaw-windows.zip"
Invoke-WebRequest -Uri $chainsawUrl -OutFile $chainsawZip

# PART 3 extract part 2 in folder of part 1
$chainsawFolderPath = Join-Path $folderPath "chainsaw"
Expand-Archive -Path $chainsawZip -DestinationPath $chainsawFolderPath
Remove-Item -Path $chainsawZip

# Download the SIGMA repository
$repoUrl = "https://github.com/SigmaHQ/sigma.git"
$destinationFolder = "C:\Program Files\Fortifier\chainsaw\sigma"
git clone $repoUrl $destinationFolder

#TODO 4: add script with content "test" to C:\Program Files (x86)\ossec-agent\active-response\bin\chainsaw.ps1
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
& 'C:\Program Files\Fortifier\chainsaw\chainsaw.exe' hunt C:\Windows\System32\winevt -s `$windows_path --mapping 'C:\Program Files\Fortifier\chainsaw\mappings\sigma-event-logs-all.yml' --from `$from --output `$env:TMP\chainsaw_output\results.json --json --level high --level critical

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
