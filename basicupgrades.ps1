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
