$certFileBaseName = 'EntraIDAppsReport'
# Create certificate
$newcert = New-SelfSignedCertificate -DnsName "EntraID Apps Report" -CertStoreLocation "cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(3) -KeySpec KeyExchange
$newcert.Thumbprint
# Export certificate to .pfx file
$newcert | Export-PfxCertificate -FilePath "$($certFileBaseName).pfx" -Password (Get-Credential).password
# Export certificate to .cer file
$newcert | Export-Certificate -FilePath "$($certFileBaseName).cer"
