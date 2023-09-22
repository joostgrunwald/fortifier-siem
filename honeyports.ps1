# Define the ports to monitor  
$portsToMonitor = @(21, 88, 3389)  
  
# Define the canary token domain  
$canaryTokenDomain = "krdu2i0a2cewpqyki0phrqgck.canarytokens.com"  
  
# Monitor for events on specified ports  
Register-ObjectEvent -InputObject (New-Object -TypeName Net.Sockets.TcpListener -ArgumentList 0) -EventName "BeginAcceptTcpClient" -SourceIdentifier "PortMonitor" -Action {  
    $port = $event.MessageData.LocalEndPoint.Port  
    if ($portsToMonitor -contains $port) {  
        Write-Host "Port $port accessed, sending DNS request to canary token domain"  
        Resolve-DnsName -Name $canaryTokenDomain -Type A -DnsOnly | Out-Null  
    }  
    $event.MessageData.Stop()  
}  
  
# Start monitoring the ports  
foreach ($port in $portsToMonitor) {  
    $listener = New-Object -TypeName Net.Sockets.TcpListener -ArgumentList $port  
    $listener.Start()  
    $listener.BeginAcceptTcpClient($null, $listener)  
}  
  
# Wait for a key press to stop the script  
Write-Host "Press any key to stop monitoring..."  
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")  
  
# Stop the listeners and remove the event  
foreach ($port in $portsToMonitor) {  
    (Get-NetTCPConnection -LocalPort $port -State Listen).OwningProcessId | ForEach-Object { Stop-Process -Id $_ -Force }  
}  
Unregister-Event -SourceIdentifier "PortMonitor"  
