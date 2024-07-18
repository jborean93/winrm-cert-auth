#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, types
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
)


def generate_ca(
    subject: str,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_key_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_key_usage, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, SHA256())
    )

    return ca_cert, ca_key


def generate_client_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    subject: str,
    user_principal_name: str,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())  # type: ignore[arg-type]

    # The UPN value is the ASN.1 encoded value. The type is predefined as
    # an OCTET_STRING and the length is the byte length of the OCTET_STRING
    # value. Technically this can fail if the length needs to be encoded in
    # more octets but for this POC it will do.
    b_upn = user_principal_name.encode()
    upn_value = b"\x0c" + int.to_bytes(len(b_upn), length=1, byteorder="big") + b_upn

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        upn_value,
                    ),
                ]
            ),
            False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False
        )
        .add_extension(ca_aki, critical=False)
        .sign(ca_key, SHA256())
    )

    return cert, key


def serialize_cert(
    cert: x509.Certificate,
    key: types.CertificateIssuerPrivateKeyTypes,
    filename: str,
    key_password: str,
    *,
    plaintext_key: bool = False,
) -> None:
    b_pub_key = cert.public_bytes(Encoding.PEM)
    b_key = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=BestAvailableEncryption(key_password.encode()),
    )

    with open(f"{filename}.pem", mode="wb") as fd:
        fd.write(b_pub_key)

    with open(f"{filename}.key", mode="wb") as fd:
        fd.write(b_key)

    if plaintext_key:
        b_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        with open(f"{filename}_no_pass.key", mode="wb") as fd:
            fd.write(b_key)


def parse_args(
    argv: list[str],
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description="Generate WinRM client auth certificates.",
    )

    parser.add_argument(
        "username",
        action="store",
        nargs=1,
        type=str,
        help="The username to generate the certificate for.",
    )

    return parser.parse_args(argv)


def main() -> None:
    args = parse_args(sys.argv[1:])

    username = args.username[0]
    ca_cert, ca_key = generate_ca("WinRM Cert Auth CA")
    client_cert, client_key = generate_client_cert(
        ca_cert, ca_key, username, f"{username}@localhost"
    )

    key_password = secrets.token_urlsafe(16)
    with open("cert_password", mode="w") as fd:
        fd.write(key_password)

    serialize_cert(ca_cert, ca_key, "ca", key_password)
    serialize_cert(
        client_cert, client_key, "client_cert", key_password, plaintext_key=True
    )


if __name__ == "__main__":
    main()
