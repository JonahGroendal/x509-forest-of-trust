#!/bin/bash
openssl x509 -in cert.pem -pubkey -noout | openssl enc -base64 -d > publickey.der
hexdump -ve '1/1 "%.2x"' pubkey.der
