Import-Module ActiveDirectory
$cert = Get-ChildItem -Path cert:\LocalMachine\My|where-object { $_.subject -like "*CA*"}
export-Certificate -cert $cert -FilePath c:\cygwin64\home\Administrator\adca.der -Type cert
