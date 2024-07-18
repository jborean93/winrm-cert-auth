#!/usr/bin/env pwsh

using namespace System.Formats.Asn1
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

#Requires -Version 7.3

[CmdletBinding()]
param (
    [Parameter(Mandatory, Position = 0)]
    [string]
    $UserName
)

$ErrorActionPreference = 'Stop'

Function New-X509Certificate {
    [OutputType([X509Certificate2])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter()]
        [HashAlgorithmName]
        $HashAlgorithm = "SHA256",

        [Parameter()]
        [X509Certificate2]
        $Issuer,

        [Parameter()]
        [X509Extension[]]
        $Extension
    )

    $key = [RSA]::Create(2048)
    $request = [CertificateRequest]::new(
        $Subject,
        $key,
        $HashAlgorithm,
        [RSASignaturePadding]::Pkcs1)


    $Extension | ForEach-Object { $request.CertificateExtensions.Add($_) }
    $request.CertificateExtensions.Add(
        [X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))

    if ($Issuer) {
        $request.CertificateExtensions.Add(
            [X509AuthorityKeyIdentifierExtension]::CreateFromCertificate($Issuer, $true, $true))

        $notBefore = $Issuer.NotBefore
        $notAfter = $Issuer.NotAfter
        $serialNumber = [byte[]]::new(9)
        [System.Random]::new().NextBytes($serialNumber)

        $cert = $request.Create($Issuer, $notBefore, $notAfter, $serialNumber)

        # For whatever reason Create does not create an X509 cert with the private key.
        [RSACertificateExtensions]::CopyWithPrivateKey($cert, $key)
    }
    else {
        $notBefore = [DateTimeOffset]::UtcNow.AddDays(-1)
        $notAfter = [DateTimeOffset]::UtcNow.AddDays(365)
        $request.CreateSelfSigned($notBefore, $notAfter)
    }
}

$keyEncParameters = [PbeParameters]::new(
    'Aes128Cbc',
    'SHA256',
    600000)

$rng = [RandomNumberGenerator]::Create()
try {
    $guidBytes = [byte[]]::new(16)
    $rng.GetBytes($guidBytes)
    $keyPass = [Guid]::new($guidBytes).Guid
}
finally {
    $rng.Dispose()
}
Set-Content cert_password -Value $keyPass

Write-Verbose "Generating CA key"
$caExt = @(
    [X509BasicConstraintsExtension]::new($true, $false, 0, $true)
    [X509KeyUsageExtension]::new("KeyCertSign", $true)
)
$ca = New-X509Certificate -Subject "CN=WinRM Cert Auth CA" -Extension $caExt
Set-Content ca.pem -Value $ca.ExportCertificatePem()

$caKey = [RSACertificateExtensions]::GetRSAPrivateKey($ca)
Set-Content ca.key -Value $caKey.ExportEncryptedPkcs8PrivateKeyPem($keyPass, $keyEncParameters)

Write-Verbose "Generating client key for '$UserName'"
$clientAuthUsageOids = [System.Security.Cryptography.OidCollection]::new()
$null = $clientAuthUsageOids.Add([Oid]::FromFriendlyName("clientAuth", "EnhancedKeyUsage"))

# .NET doesn't have a nice way to build this so we write the ASN.1 data manually.
<#
GeneralName ::= CHOICE {
    otherName                       [0]     OtherName,
    rfc822Name                      [1]     IA5String,
    dNSName                         [2]     IA5String,
    x400Address                     [3]     ORAddress,
    directoryName                   [4]     Name,
    ediPartyName                    [5]     EDIPartyName,
    uniformResourceIdentifier       [6]     IA5String,
    iPAddress                       [7]     OCTET STRING,
    registeredID                    [8]     OBJECT IDENTIFIER }

OtherName ::= SEQUENCE {
    type-id    OBJECT IDENTIFIER,
    value      [0] EXPLICIT ANY DEFINED BY type-id }
#>
$asnWriter = [AsnWriter]::new('DER')
$otherScope = $asnWriter.PushSequence()
$valueTag = $asnWriter.PushSequence([Asn1Tag]::new('ContextSpecific', 0, $true))
$asnWriter.WriteObjectIdentifier("1.3.6.1.4.1.311.20.2.3")  # MS userPrincipalName
$utf8Tag = $asnWriter.PushSequence([Asn1Tag]::new('ContextSpecific', 0, $true))
$asnWriter.WriteCharacterString('UTF8String', "$UserName@localhost")
$utf8Tag.Dispose()
$valueTag.Dispose()
$otherScope.Dispose()
$upnSan = $asnWriter.Encode()

$clientExt = @(
    [X509EnhancedKeyUsageExtension]::new($clientAuthUsageOids, $false)
    [X509SubjectAlternativeNameExtension]::new($upnSan, $false)
)
$client = New-X509Certificate -Subject "CN=$UserName" -Issuer $ca -Extension $clientExt
Set-Content client_cert.pem -Value $client.ExportCertificatePem()

$clientKey = [RSACertificateExtensions]::GetRSAPrivateKey($client)
Set-Content client_cert.key -Value $clientKey.ExportEncryptedPkcs8PrivateKeyPem($keyPass, $keyEncParameters)
Set-Content client_cert_no_pass.key -Value $clientKey.ExportPkcs8PrivateKeyPem()
