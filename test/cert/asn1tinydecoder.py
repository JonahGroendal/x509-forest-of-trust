
# This is a simple and fast ASN1 decoder without external libraries.
#
# In order to browse through the ASN1 structure you need only 3
# functions allowing you to navigate:
#    asn1_node_root(...), asn1_node_next(...) and asn1_node_first_child(...)
#
####################### BEGIN ASN1 DECODER ############################

# Author: Jens Getreu, 8.11.2014

##### NAVIGATE

# The following 4 functions are all you need to parse an ASN1 structure

# gets the first ASN1 structure in der
def asn1_node_root(der):
	return asn1_read_length(der,0)

# gets the next ASN1 structure following (ixs,ixf,ixl)
def asn1_node_next(der, (ixs,ixf,ixl)):
	return asn1_read_length(der,ixl+1)

# opens the container (ixs,ixf,ixl) and returns the first ASN1 inside
def asn1_node_first_child(der, (ixs,ixf,ixl)):
	if ord(der[ixs]) & 0x20 != 0x20:
		raise ValueError('Error: can only open constructed types. '
				+'Found type: 0x'+der[ixs].encode("hex"))
	return asn1_read_length(der,ixf)

# is true if one ASN1 chunk is inside another chunk.
def asn1_node_is_child_of((ixs,ixf,ixl), (jxs,jxf,jxl)):
	return ( (ixf <= jxs ) and (jxl <= ixl) ) or \
           ( (jxf <= ixs ) and (ixl <= jxl) )

##### END NAVIGATE



##### ACCESS PRIMITIVES

# get content and verify type byte
def asn1_get_value_of_type(der,(ixs,ixf,ixl),asn1_type):
	asn1_type_table = {
	'BOOLEAN':           0x01,	'INTEGER':           0x02,
	'BIT STRING':        0x03,	'OCTET STRING':      0x04,
	'NULL':              0x05,	'OBJECT IDENTIFIER': 0x06,
	'SEQUENCE':          0x70,	'SET':               0x71,
	'PrintableString':   0x13,	'IA5String':         0x16,
	'UTCTime':           0x17,	'ENUMERATED':        0x0A,
	'UTF8String':        0x0C,	'PrintableString':   0x13,
	}
	if asn1_type_table[asn1_type] != ord(der[ixs]):
		raise ValueError('Error: Expected type was: '+
			hex(asn1_type_table[asn1_type])+
			' Found: 0x'+der[ixs].encode('hex'))
	return der[ixf:ixl+1]

# get value
def asn1_get_value(der,(ixs,ixf,ixl)):
	return der[ixf:ixl+1]

# get type+length+value
def asn1_get_all(der,(ixs,ixf,ixl)):
	return der[ixs:ixl+1]

##### END ACCESS PRIMITIVES



##### HELPER FUNCTIONS

# converter
def bitstr_to_bytestr(bitstr):
	if bitstr[0] != '\x00':
		raise ValueError('Error: only 00 padded bitstr can be converted to bytestr!')
	return bitstr[1:]

# converter
def bytestr_to_int(s):
	# converts bytestring to integer
	i = 0
	for char in s:
		i <<= 8
		i |= ord(char)
	return i

# ix points to the first byte of the asn1 structure
# Returns first byte pointer, first content byte pointer and last.
def asn1_read_length(der,ix):
	first= ord(der[ix+1])
	if  (ord(der[ix+1]) & 0x80) == 0:
		length = first
		ix_first_content_byte = ix+2
		ix_last_content_byte = ix_first_content_byte + length -1
	else:
		lengthbytes = first & 0x7F
		length = bytestr_to_int(der[ix+2:ix+2+lengthbytes])
		ix_first_content_byte = ix+2+lengthbytes
		ix_last_content_byte = ix_first_content_byte + length -1
	return (ix,ix_first_content_byte,ix_last_content_byte)

##### END HELPER FUNCTIONS


####################### END ASN1 DECODER ############################
