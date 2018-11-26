#!/bin/bash
openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
openssl x509 -outform der -in cert.pem -out cert.der
openssl x509 -in cert.pem -pubkey -noout | openssl enc -base64 -d > publickey.der
openssl x509 -noout -fingerprint -sha256 -inform pem -in cert.pem -out fingerprint.txt
