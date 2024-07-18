#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param ()

Write-Verbose -Message "Disabling WSMan Certificate authentication"
Set-Item -LiteralPath WSMan:\localhost\Service\Auth\Certificate -Value False

Write-Verbose -Message "Removing temp certificate file"
Remove-Item -Path C:\Windows\TEMP\*.pem

Get-ChildItem -Path WSMan:\localhost\ClientCertificate | ForEach-Object {
    $info = [Ordered]@{}
    $_.Keys | ForEach-Object {
        $key, $value = $_ -split '=', 2
        $info[$key] = $value
    }
    Write-Verbose -Message "Processing cert map for '$($_.Name)' - Subject: '$($info.Subject)', Issuer: $($info.Issuer), URI: '$($info.URI)'"

    # The UserName value isn't exposed in the WSMan provider so we get it
    # through the registry. We use this to determine what user to remove.
    $mappedUser = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\CertMapping\*' | ForEach-Object {
        if (
            $_.GetValue('Subject', '') -eq $info.Subject -and
            $_.GetValue('Uri', '') -eq $info.URI -and
            ($user = $_.GetValue('UserName', ''))
        ) {
            Write-Verbose "Found mapped user entry '$user'"
            $user
        }
    } | Select-Object -First 1

    if ($mappedUser -and ($localUser = Get-LocalUser -Name $mappedUser -ErrorAction SilentlyContinue)) {
        Write-Verbose -Message "Removing local user '$mappedUser'"
        $localUser | Remove-LocalUser
    }

    if ($info.Subject) {
        Get-ChildItem -LiteralPath Cert:\LocalMachine\TrustedPeople |
            # UpnName is the userPrincipalName SAN entry.
            Where-Object { $_.GetNameInfo('UpnName', $false) -eq $info.Subject } |
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

    Write-Verbose -Message "Removing cert map '$($_.Name)'"
    $_ | Remove-Item -Force -Recurse
}
