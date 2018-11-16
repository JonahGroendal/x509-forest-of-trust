#!/bin/bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
openssl x509 -outform der -in self-signedCert.pem -out self-signedCert.der
openssl x509 -in self-signedCert.pem -pubkey -noout | openssl enc -base64 -d > publickey.der
