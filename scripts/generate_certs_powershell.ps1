#Requires -Version 5.1

using namespace System.IO
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding()]
param (
    [Parameter(Mandatory, Position = 0)]
    [string]
    $UserName
)

$ErrorActionPreference = 'Stop'

Function Remove-CertificateAndKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [X509Certificate2]
        $Certificate,

        [Parameter(Mandatory)]
        [string]
        $KeyName
    )

    # This the path CNG uses to store the key
    $keyPath = [Path]::Combine($env:AppData, 'Microsoft', 'Crypto', 'Keys', $KeyName)
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($Certificate.Thumbprint)" -Force
    if (Test-Path -LiteralPath $keyPath) {
        Remove-Item -LiteralPath $keyPath -Force
    }
}

$rng = [RandomNumberGenerator]::Create()
try {
    $guidBytes = [byte[]]::new(16)
    $rng.GetBytes($guidBytes)
    $keyPass = [Guid]::new($guidBytes).Guid
    Set-Content -Path cert_password -Value $keyPass
}
finally {
    $rng.Dispose()
}

$ca = $caKeyName = $client = $clientKeyName = $null
try {
    $caParams = @{
        Extension = @(
            [X509BasicConstraintsExtension]::new($true, $false, 0, $true)
            [X509KeyUsageExtension]::new('KeyCertSign', $true)
        )
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter = (Get-Date).AddYears(1)
        Provider = 'Microsoft Software Key Storage Provider'
        Subject = 'CN=WinRM Cert Auth CA'
        Type = 'Custom'
    }
    Write-Verbose -Message "Creating CA certificate"
    $ca = New-SelfSignedCertificate @caParams

    # We need to get the key name, Export as a pfx seems to change the stored
    # key to an ephemeral one on the X509Certificate2. By doing it now we get
    # the actual stored key info.
    $caKeyName = [RSACertificateExtensions]::GetRSAPrivateKey($ca).Key.UniqueName

    $clientParams = @{
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter = $caParams.NotAfter
        Provider = 'Microsoft Software Key Storage Provider'
        Signer = $ca
        Subject = "CN=$UserName"
        TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2","2.5.29.17={text}upn=$UserName@localhost")
        Type = 'Custom'
    }
    Write-Verbose -Message "Creating client certificate for '$UserName'"
    $client = New-SelfSignedCertificate @clientParams
    $clientKeyName = [RSACertificateExtensions]::GetRSAPrivateKey($client).Key.UniqueName

    Set-Content -Path "ca.pem" -Value @(
        "-----BEGIN CERTIFICATE-----"
        [Convert]::ToBase64String($ca.RawData) -replace ".{64}", "$&`n"
        "-----END CERTIFICATE-----"
    )
    $caPfxBytes = $ca.Export('Pfx', $keyPass)
    [File]::WriteAllBytes("$pwd\ca.pfx", $caPfxBytes)

    Set-Content -Path "client_cert.pem" -Value @(
        "-----BEGIN CERTIFICATE-----"
        [Convert]::ToBase64String($client.RawData) -replace ".{64}", "$&`n"
        "-----END CERTIFICATE-----"
    )
    $clientPfxBytes = $client.Export('Pfx', $keyPass)
    [File]::WriteAllBytes("$pwd\client_cert.pfx", $clientPfxBytes)
}
finally {
    if ($ca) {
        Remove-CertificateAndKey -Certificate $ca -KeyName $caKeyName
    }
    if ($client) {
        Remove-CertificateAndKey -Certificate $client -KeyName $clientKeyName
    }
}
