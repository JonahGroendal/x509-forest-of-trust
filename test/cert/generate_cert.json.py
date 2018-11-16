'''
Extracts data from self-signedCert.der to be used in X509InTreeOfTrust.js
'''

from asn1tinydecoder import asn1_node_root, asn1_get_all, asn1_get_value, \
                        asn1_get_value_of_type, asn1_node_next, asn1_node_first_child, \
                        asn1_read_length, asn1_node_is_child_of, \
                        bytestr_to_int, bitstr_to_bytestr
import hashlib

m = hashlib.sha256()

with open('self-signedCert.der') as f:
    der = f.read()

i = asn1_node_root(der)
i = asn1_node_first_child(der,i)

signed_content_ptr = i
signed_content = asn1_get_all(der, signed_content_ptr)
message = "0x" + signed_content.encode("hex");

j = asn1_node_next(der, i)
j = asn1_node_next(der, j)

signature = "0x" + asn1_get_value(der, j).encode("hex")

i = asn1_node_first_child(der,i)
i = asn1_node_first_child(der,i)
i = asn1_node_next(der, i)

encoded_serial_number = str(asn1_get_value(der, i).encode('hex'))
serial_number_list = list(encoded_serial_number)
for _ in range(64-len(serial_number_list)):
    serial_number_list.insert(0, "0")
serial_number = "0x" + "".join(serial_number_list)

i = asn1_node_next(der, i)
i = asn1_node_next(der, i)

j = asn1_node_first_child(der, i)
j = asn1_node_next(der, j)
j = asn1_node_next(der, j)
j = asn1_node_next(der, j)
j = asn1_node_next(der, j)
j = asn1_node_next(der, j)
j = asn1_node_first_child(der, j)
j = asn1_node_first_child(der, j)
j = asn1_node_next(der, j)
common_name = asn1_get_value(der, j);

i = asn1_node_next(der, i)
i = asn1_node_next(der, i)
i = asn1_node_next(der, i)

expected_pub_key = asn1_get_all(der, i)
expected_pub_key = "0x" + expected_pub_key.encode("hex")

with open('cert.json', 'w+') as f:
    f.write('{\n')
    f.write('   "tbsCertificate": "' + message + '",\n')
    f.write('   "signature": "' + signature + '",\n')
    f.write('   "expectedPubKey": "' + expected_pub_key + '",\n')
    f.write('   "expectedSerialNumber": "'+ serial_number + '",\n')
    f.write('   "expectedCommonName": "'+ common_name + '",\n')
    f.write('   "signersPubKey": "' + expected_pub_key + '"\n')
    f.write('}')
