# Generate random passwords  
function Generate-Password {  
    param (  
        [int]$Length = 12  
    )  
  
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"  
    return -join ((1..$Length) | ForEach-Object { Get-Random -InputObject $chars })  
}  
  
# Generate random commands  
function Generate-Command {  
    $commands = @("dir", "ipconfig", "netstat", "ping", "tracert", "whoami", "nslookup", "route", "arp", "nbtstat")  
    $randomCommand = Get-Random -InputObject $commands  
    $randomIpAddress = "{0}.{1}.{2}.{3}" -f (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 1 -Maximum 255)  
    $randomArgs = @("", "-a", "-n", "-r", "-p")  
  
    if ($randomCommand -eq "ping" -or $randomCommand -eq "tracert" -or $randomCommand -eq "nslookup") {  
        $randomCommand += " $randomIpAddress"  
    }  
  
    $randomCommand += " $(Get-Random -InputObject $randomArgs)"  
    return $randomCommand  
}  
  
# Add generated commands and passwords to CMD and PowerShell history  
function Add-FakeHistory {  
    $historyCount = 50  
  
    # Add to CMD history  
    $cmdHistoryFile = "$env:USERPROFILE\AppData\Local\Microsoft\Windows\PowerShell\CommandAnalyzer\CommandHistory.txt"  
    for ($i = 0; $i -lt $historyCount; $i++) {  
        Add-Content -Path $cmdHistoryFile -Value (Generate-Command)  
        Add-Content -Path $cmdHistoryFile -Value (Generate-Password)  
    }  
  
    # Add to PowerShell history  
    $psHistoryFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"  
    for ($i = 0; $i -lt $historyCount; $i++) {  
        Add-Content -Path $psHistoryFile -Value (Generate-Command)  
        Add-Content -Path $psHistoryFile -Value (Generate-Password)  
    }  
}  
  
# Execute the function to add fake history  
Add-FakeHistory  
