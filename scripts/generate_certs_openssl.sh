#!/usr/bin/env bash

set -o pipefail -eux

if [ $# -lt 1 ]; then
    echo "Error: The username must be provided."
    echo "Usage: $0 <username>"
    exit 1
fi

USERNAME="${1}"
PASSWORD="$( openssl rand -base64 12 )"

echo "${PASSWORD}" > cert_password

echo "Generating CA certificate"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]
[v3_ca]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign
EOL

openssl genrsa \
    -aes256 \
    -out ca.key \
    -passout pass:"${PASSWORD}"

openssl req \
  -new \
  -sha256 \
  -subj "/CN=WinRM Cert Auth CA" \
  -newkey rsa:2048 \
  -keyout ca.key \
  -out ca.csr \
  -config openssl.conf \
  -reqexts v3_ca \
  -passin pass:"${PASSWORD}" \
  -passout pass:"${PASSWORD}"

openssl x509 \
  -req \
  -in ca.csr \
  -sha256 \
  -out ca.pem \
  -days 365 \
  -key ca.key \
  -extfile openssl.conf \
  -extensions v3_ca \
  -passin pass:"${PASSWORD}"

echo "Generating CA certificate for ${USERNAME}"
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name

[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:${USERNAME}@localhost
EOL

openssl req \
  -new \
  -sha256 \
  -subj "/CN=${USERNAME}" \
  -newkey rsa:2048 \
  -keyout client_cert.key \
  -out client_cert.csr \
  -config openssl.conf \
  -reqexts v3_req_client \
  -passin pass:"${PASSWORD}" \
  -passout pass:"${PASSWORD}"

openssl x509 \
  -req \
  -in client_cert.csr \
  -sha256 \
  -out client_cert.pem \
  -days 365 \
  -extfile openssl.conf \
  -extensions v3_req_client \
  -passin pass:"${PASSWORD}" \
  -CA ca.pem \
  -CAkey ca.key \
  -CAcreateserial

openssl rsa \
  -in client_cert.key \
  -out client_cert_no_pass.key \
  -passin pass:"${PASSWORD}"

rm openssl.conf
rm client_cert.csr
rm ca.csr
rm ca.srl
