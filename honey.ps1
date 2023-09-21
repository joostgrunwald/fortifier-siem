# Define the list of honeytokens  
$honeytokens = @(  
    "Aantekeningen voor mezelf.docx",  
    "aws_api",  
    "aws_api_key",  
    "Azure Service Principal Certificate",  
    "Azure SP Certificate",  
    "Backup informatie.docx",  
    "Backup wachtwoorden.docx",  
    "database exports.xlsx",  
    "db.ini.zip",  
    "edudb_mysql.sql.gz",  
    "edudb_mysql_dump.sql.gz",  
    "Hoe log in ik in de cloud?.docx",  
    "Keypass wachtwoord.docx",  
    "kubeconfig",  
    "mysql_nuwelijn.sql.gz",  
    "Nieuwe wachtwoorden.docx",  
    "Oude database.docx",  
    "passwords.xlsx",  
    "Root variables.docx",  
    "salarisoverzicht.xlsx",  
    "salarisstrooken.zip",  
    "Uitleg inloggen.docx",  
    "Uitleg keyvault.docx",  
    "usernames.xlsx",  
    "wachtwoorden.zip",  
    "Wachtwoorden oude database.docx"  
)  
  
# Define the locations to hide honeytokens  
$locations = @(  
    "$env:ProgramData",  
    "$env:ProgramData\Microsoft",  
    "$env:UserProfile\AppData\Local\Temp",  
    "$env:UserProfile\AppData\Roaming",  
    "$env:UserProfile\AppData\Roaming\Microsoft",  
    "$env:UserProfile\Documents",  
    "$env:SystemRoot\System32",  
    "$env:SystemRoot\System32\config"  
    "$env:ProgramFiles",  
    "$env:ProgramFiles(x86)",  
    "C:\"  
)  

# Create folders and hide honeytokens  
foreach ($location in $locations) {  
    # pick 2 random honeytokens
    $honeytoken1 = $honeytokens | Get-Random
    $honeytoken2 = $honeytokens | Get-Random

    # get file honeytoken in current dir
    $honeytoken1 = Get-Item $honeytoken1
    $honeytoken2 = Get-Item $honeytoken2

    # create copy of file in $location
    Copy-Item $honeytoken1.FullName $location
}  
