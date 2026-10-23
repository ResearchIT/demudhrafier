#!/usr/bin/python
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import argparse
from pathlib import Path

subjects = ["CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL", "CN=EM OV TLS CA - G3B,O=eMudhra BV,C=NL", "CN=EM EV TLS CA - G3B,O=eMudhra BV,C=NL", "CN=EM DV TLS CA - G3C,O=eMudhra Inc,C=US", "CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US", "CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US", "CN=EM OV CS CA - G3B,O=eMudhra BV,C=NL", "CN=EM OV CS CA - G3C,O=eMudhra Inc,C=US", "CN=emSign Root TLS CA - G3,O=eMudhra Technologies Limited,C=IN", "CN=emSign Root CS CA - G3,O=eMudhra Technologies Limited,C=IN", "CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB", "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN"]

parser = argparse.ArgumentParser(description="removes untrusted emudhra certs and those revoked comodo certs that cross signed some of the intermediaries")
parser.add_argument("cabundle", type=Path)

args = parser.parse_args()
with open(args.cabundle, "rb") as bundle:
    certs = x509.load_pem_x509_certificates(bundle.read())
if not certs:
    raise RuntimeError("Failed to read in certificate bundle.")
print(f"Loaded {len(certs)} certificates from bundle")

good_certs = []

for cert in certs:
    subject = cert.subject.rfc4514_string()
    if subject in subjects:
        print(f"Removing {subject}")
    else:
        good_certs.append(cert)
if len(certs) == len(good_certs):
    print("No certificates were filtered. Exiting.")
    exit(0)
with open(args.cabundle, "wb") as bundle:
    for cert in good_certs:
        bundle.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
print(f"Overwrote {args.cabundle} with {len(good_certs)} certs from filtered bundle")
