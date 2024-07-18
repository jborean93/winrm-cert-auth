#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param ()

Write-Verbose -Message "Disabling WSMan Certificate authentication"
Set-Item -LiteralPath WSMan:\localhost\Service\Auth\Certificate -Value False

Write-Verbose -Message "Removing temp certificate file"
Remove-Item -Path C:\Windows\TEMP\*.pem

Get-ChildItem -Path WSMan:\localhost\ClientCertificate | ForEach-Object {
    Write-Verbose -Message "Processing cert map for '$($_.Name)'"

    $info = [Ordered]@{}
    $_.Keys | ForEach-Object {
        $key, $value = $_ -split '=', 2
        $info[$key] = $value
    }

    if ($info.Subject) {
        $username = $info.Subject
        $upnSplit = $username.LastIndexOf('@')
        if ($upnSplit -ne -1) {
            $username = $username.Substring(0, $upnSplit)
        }

        $localUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
        if ($localUser) {
            Write-Verbose -Message "Removing local user '$username'"
            $localUser | Remove-LocalUser
        }

        Get-ChildItem -LiteralPath Cert:\LocalMachine\TrustedPeople |
            Where-Object Subject -eq "CN=$username" |
            ForEach-Object {
                Write-Verbose -Message "Removing TrustedPeople entry for '$($_.Subject)' $($_.Thumbprint)"
                $_ | Remove-Item -Force
            }
    }

    if ($info.Issuer) {
        $issuerCert = Get-Item -LiteralPath "Cert:\LocalMachine\Root\$($info.Issuer)" -ErrorAction SilentlyContinue
        if ($issuerCert) {
            Write-Verbose -Message "Removing Issuer CA cert '$($issuerCert.Subject)' $($info.Issuer)"
            $issuerCert | Remove-Item -Force
        }
    }
}
