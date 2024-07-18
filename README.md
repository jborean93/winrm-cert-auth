# WinRM Client Certificate Authentication
This repo demonstrates how to create certificates for WinRM/WSMan client certificate authentication and how to configure Windows to setup the service side to allow those certificates for client authentication.
It has some Ansible playbooks that can be used to do all the necessary steps plus some standalone scripts and background information to help you understand how certificate authentication works and is configured.

## Background
WinRM authentication is typically done through the `Negotiate` protocol which attempts to use `Kerberos` authentication before falling back to `NTLM`.
It is possible to use client certificates through the TLS X.509 client certificate authentication but the documentation around this is hard to come by and hard to understand.
This repo will attempt to show how to both generate those certificates and how to configure the Windows host to use them for authentication.
It will also show how those certificates can be used in Ansible to perform certificate authentication.

Please keep in that certificate authentication does have its downsides such as:

+ it can only be mapped to a local Windows user, no domain accounts
+ the username and password must be mapped to the certificate, if the password changes, the cert will need to be re-mapped
+ an administrator on the Windows host can retrieve the local user password through the certificate mapping
+ the HTTP libraries used by `psrp` and `winrm` do not support
  + encrypted private keys, they must be stored without encryption
  + certs and private keys stored as a var, they must be a file

Usually these points are blockers (the last one especially) but if you are still interested then read on.

## Requirements
+ Windows host with a HTTPS WinRM listener configured
+ Ansible collections
  + `ansible.windows` - Used to configured the Windows host
  + `community.crypto` - Used in `setup_certificate.yml`
+ Python libraries `winrm` and `psrp` for testing the connection

To install the Python libraries we can run:

```bash
python3 -m pip install pypsrp winrm
```

To install the required collections run

```bash
ansible-galaxy collection install -r requirements.yml
```

If you are not using `setup_certificate.yml` to generate the certificates, then `community.crypto` will not be needed.

## How to run
Before running we need to add in the inventory details for our Windows host.
Edit [inventory.ini](./inventory.ini) and add the Windows host hostname/IP under the `[windows]` section.
Also set the `ansible_user` and `ansible_password` value under the `[windows:vars]` section.
We can verify that it worked by running `ansible -i inventory.ini windows -m ansible.windows.win_ping`.

Once the inventory has been setup we run the following playbooks with the `CERT_USER` set to the Windows user we want to create that's mapped to the certificate:

```bash
CERT_USER=AnsibleCertUser
ansible-playbook -i inventory.ini setup_certificate.yml -e username=$CERT_USER
ansible-playbook -i inventory.ini setup_windows.yml -e username=$CERT_USER
```

The first playbook [setup_certificate.yml](./setup_certificate.yml) is run on localhost and will create the CA and client authentication certificates/keys.
When run, it will create the folder `cert` with the certificates and keys and the last task will contain a brief summary:

```yaml
ok: [localhost] =>
    msg: CA and Client Certificate has been generated at '/home/.../winrm-cert-auth/cert'.
        The password for both private keys is '...'.
```

You can also generate the certificate manually using OpenSSL or with PowerShell on the Windows host, see [Certificate Generation](#certificate-generation) for more details.

The second playbook [setup_windows.yml](./setup_windows.yml) will configure the Windows host by creating the local user, setting up the certificates, and mapping the cert to the created user.
When run, it will output the user details and also point to a generated inventory you can use to test certificate auth called `cert_inventory.ini`.

```yaml
ok: [win-host] =>
    msg: WinRM service and username have been configured. The remote user 'AnsibleCertUser'
        has been configured with the password '...'. Use the '/home/.../winrm-cert-auth/cert_inventory.ini'
        inventory file to connect to the remote host with the client certificate.
```

Finally we can test the certificate authentication by running:

```bash
ansible -i cert_inventory.ini windows -m ansible.windows.win_command -a whoami
```

This will test out the certificate authentication for both the `psrp` and `winrm` connection plugin and should output `...\ansiblecertuser`.

## More Information
WinRM certificate authentication works like TLS/HTTPS client certificate that are used more in enterprise environments.
Typically in a normal TLS handshake, only the server sends its certificate but with client authentication the client will also provide its own certificate to prove its identity.

> [!NOTE]
> While it makes no difference to the end user it is important to note that WinRM's certificate auth uses a post handshake certificate request rather than forcing it as part of the initial TLS handshake. This allows WinRM to still be used for other authentication options over HTTPS and only require the cert if the client requests that method during authentication.

For a client to provide the certificate it needs to have access to the private key and public certificate.
Only the public certificate is sent across the wire, the private key is used to generate values that can prove to the server the client has the key without actually sending the key.

When the client attempts to use certificate authentication with WinRM it:

+ builds the TLS context with the client cert and key ready to be used for authentication
+ sets the `Authorization` header with the value `http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual`
+ sends the WSMan request to the server
+ the server sees the `Authorization` header and requests a certificate on the TLS layer
+ the client provides the certificate public key and continues the exchange

The server does the following checks based on the certificate provided by the client (there might be more checks I am missing):

+ the certificate is issued by a trusted Certificate Authority (CA)
    + if self signed, the cert must be trusted as a root CA
+ the certificate has an Extended Key Usage (EKU) of `clientAuth` (`1.3.6.1.5.5.7.3.2`)
+ the certificate itself is stored in the `LocalMachine` `TrustedPeople` certificate store
+ the Subject Alternative Name (SAN) contains an `otherName` entry for `userPrincipalName` (`1.3.6.1.4.1.311.20.2.3`) (typically with the value `username@localhost`)
+ a `WSMan:\localhost\ClientCertificate` mapping has a `Subject` with the same SAN value from the above
+ the username/password registered for the mapping above is a valid local user and the and the user can be logged in with the password
+ the standard authorization checks done by WinRM for the above user (Administrator, allowed to log onto network, not disabled, etc)

If any of the above checks fail the authentication fails.
If they all succeed, the WinRM task will be run as the user the certificate is mapped to.

### Certificate Generation
The playbook [setup_certificate.yml](./setup_certificate.yml) can be used to generate a CA cert/key and a cert/key associated with a particular username.
It is possible to use OpenSSL, PowerShell, or Python to generate these certificates if you don't wish to use the playbook.

The first step is to generate a CA certificate which will be used to issue our client certificate.

> [!NOTE]
> While a CA is not strictly needed, it is done in this example to show you how this certificate can be generated and signed by any CA cert.
> It is recommened to use a proper CA that is trusted in your environment, for example one issued by Active Directory Certificate Services (ADCS).

Once we have a CA we can then generate a client certificate and key that is issued/signed by our CA key.
The client certificate *MUST* have an EKU with `clientAuth` set and a SAN with an `otherName` value for a `userPrincipalName`.
The certificate *SHOULD* set the subject to `CN=username` and the SAN `userPrincipalName` to `username@localhost` where the `username` is the local user we are mapping the cert to.
While the subject and SAN should have these values they are not strictly necessary, the subject is not used and the SAN `userPrincipalName` is the value used in the WSMan mapping.

The following scripts can be used to generate the CA and client certificates:

+ [bash - generate_certs_openssl.sh](./scripts/generate_certs_openssl.sh) - Requires OpenSSL
+ [powershell - generate_certs_powershell.ps1](./scripts/generate_certs_powershell.ps1) - Windows Only 5.1/7+
+ [powershell 7+ - generate_certs_pwsh.ps1](./scripts/generate_certs_pwsh.ps1) -  PowerShell 7+ Windows/Linux/macOS
+ [python - generate_certs_python.py](./scripts/generate_certs_python.py) - Requires the `cryptography` Python package

All these scripts require the username to be provided as the first argument.
This **SHOULD** match the username being created on the Windows host but it is not a hard requirement.

Once generated, Ansible requires the public cert and private key in the PEM format as separate files.
The private key cannot be encrypted due to a limitation in the underlying libraries that Ansible uses.

If you are wanting to use certificate auth from a Windows client with PowerShell then Windows must have access to the private key.
The simplest way to do this is to convert the cert and key into a PKCS12/pfx file and import it into Windows with.
To convert the separate cert and key into a PFX we can use OpenSSL

```bash

```

Once we have a pfx file we can import that into Windows with:

```powershell
$pfxPass = Read-Host -Prompt "Enter the pfx password" -AsSecureString
$importParams = @{
    CertStoreLocation = 'Cert:\CurrentUser\My'
    FilePath = '...'  # Replace with the path to the pfx generated above
    Password = $pfxPass
}
$cert = Import-PfxCertificate @importParams
$cert.Thumbprint
```

From there we can use the `-CertificateThumbprint $thumbprint` parameter on cmdlets like `Invoke-Command/Enter-PSSession` for the user we imported the certificate with.

### Windows Configuration
Once the certificates have been generated we need to configure Windows to use those certificates.
The following things must be done on Windows to configure the certificate authentication:

+ trust the CA that issued our client certificate
  + if using a self signed client certificate this will be the client certificate itself
+ trust the client certificate as a `TrustedPeople` cert
+ create the local user
+ creates a wsman certificate mapping entry that
  + sets the `Subject` to the SAN `userPrincipalName` entry of our client certificate
  + sets the `Uri` to `*`
  + sets the `Issuer` to the root CA thumbprint that issued our client certificate
  + provides the username/password of the local user to map the certificate toß
+ enabled the Certificate authentication option on the WSMan service

The playbook [setup_windows.yml](./setup_windows.yml) is designed to do all this as part of the Ansible run but if you wish to do this manually through PowerShell you can use [setup_windows.ps1](./scripts/setup_windows.ps1) instead.

> [!NOTE]
> This script needs to be run as admin.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File setup_windows.ps1 -CACert ca.pem -ClientCert client_cert.pem -Verbose
```

The script will create a local user based on the `Subject` of the `client_cert.pem` provided.
The password for the user is not needed for anything but will be randomly generated and outputted to the console just in case you want to use it for something else.

### Reset Changes
The PowerShell script [reset_windows.ps1](./scripts/reset_windows.ps1) can be run to undo the Windows configuration done by the playbook.
This script will disable cert auth, remove any WSMan certificate mappings, delete the local user for each mapping, and remove the imported certifices.

> [!WARNING]
> Do not run this script if you have certificate authentication configured for any other users, it is designed to bring the WinRM service back to the factory state when it comes to certificate authentication make by this example repo.

You can copy the script and run it on the Windows host or you can run it through Ansible:

```bash
ansible \
    -i inventory.ini \
    windows \
    -m ansible.windows.win_powershell \
    -a '{"script": "{{ lookup(\"file\", \"scripts/reset_windows.ps1\") }}", "parameters": {"Verbose": true}}'
```