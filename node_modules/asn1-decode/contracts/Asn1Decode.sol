pragma solidity  ^0.4.23;
pragma experimental ABIEncoderV2;

contract Asn1Decode {
  /*
   * Points to a node in a der-encoded asn1 sturture (which is a bytes array)
   */
  struct NodePtr {
    uint ixs; // first byte index
    uint ixf; // first content byte index
    uint ixl; // last content byte index
  }
  /*
   * First step in traversing an asn1 structure
   *
   * @param der The der-encoded asn1 structure
   * @return a NodePtr object pointing to the outermost node
   */
  function nodeRoot(bytes der) public pure returns (NodePtr) {
  	return asn1_read_length(der, 0);
  }

  /*
   * Get the next sibling node
   *
   * @param der The der-encoded asn1 structure
   * @param n The current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function nodeNext(bytes der, NodePtr n) public pure returns (NodePtr) {
  	return asn1_read_length(der, n.ixl+1);
  }

  /*
   * Get the first child node of the current node
   *
   * @param der The der-encoded asn1 structure
   * @param n The current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function nodeFirstChild(bytes der, NodePtr n) public pure returns (NodePtr) {
    // Can only open constructed types
  	require(der[n.ixs] & 0x20 == 0x20);
  	return asn1_read_length(der, n.ixf);
  }

  /*
   * Returs true if j is child of i or if i is child of j. Used for looping
   * through children of a given node (either i or j).
   *
   * @param i Pointer to an asn1 node
   * @param j Pointer to another asn1 node of the same asn1 structure
   * @return weather i or j is the direct child of the other.
   */
  function nodeIsChildOf(NodePtr i, NodePtr j) public pure returns (bool) {
  	return ( ((i.ixf <= j.ixs) && (j.ixl <= i.ixl)) ||
             ((j.ixf <= i.ixs) && (i.ixl <= j.ixl)) );
  }
  /*
   * @dev Traverses a der-encoded chunk of bytes by repeatedly using nodeNext and
   * nodeFirstChild in an alternating fashion.
   *
   * @param der The der-encoded asn1 structure to traverse
   * @param location The encoded traversal instructions
   *    - every even-index byte performes a nodeNext() operation a number of
          times equal to its value
   *    - every odd-index byte performs a nodeFirstChild() operation a number of
          times equal to its value
   *    ex: \x00\x02\x01 performs nodeRoot() then  (0 x nodeNext()) then
          (2 x nodeFirstChild()) then (1 x nodeNext())
   *
   *  @return a NodePtr struct pointing to the index of the node traversed to
   */
   bytes constant public COMMON_NAME = "\x55\x04\x03";
   // shortcuts to commonly used X509 nodes
   bytes constant public LOCATION_SERIAL_NUMBER = '\x00\x02\x01';
   bytes constant public LOCATION_VALID_NOT_BEFORE = '\x00\x02\x04\x01';
   bytes constant public LOCATION_VALID_NOT_AFTER = '\x00\x02\x04\x01\x01';
   bytes constant public LOCATION_PUB_KEY = '\x00\x02\x06';
  function nodeTraverse(bytes der, bytes location) public pure returns (NodePtr) {
    NodePtr memory i;
    uint8 j;
    uint8 k;

    i = nodeRoot(der);
    for (j=0; j<location.length; j++) {
      if (j % 2 == 0) {
        for (k=0; k<uint8(location[j]); k++) {
          i = nodeNext(der, i);
        }
      } else {
        for (k=0; k<uint8(location[j]); k++) {
          i = nodeFirstChild(der, i);
        }
      }
    }

    return i;
  }

  // Get the value of the node
  function getValue(bytes der, NodePtr n) public pure returns (bytes) {
    uint valueLength = n.ixl + 1 - n.ixf;
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[n.ixf + i];
    }
  	return ret;
  }

  // Get the entire node
  function getAll(bytes der, NodePtr n) public pure returns (bytes) {
    uint valueLength = n.ixl + 1 - n.ixs;
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[n.ixs + i];
    }
  	return ret;
  }

  function decodeBitstring(bytes bitstr) public pure returns (bytes) {
    // Only 00 padded bitstr can be converted to bytestr!
  	require(bitstr[0] == 0x00);
  	bytes memory ret = new bytes(bitstr.length-1);
    for (uint i=0; i<ret.length; i++) {
      ret[i] = bitstr[i+1];
    }
  	return ret;
  }

  // Might need to be looked at / tested thoroughly
  function decodeUint(bytes encodedUint) public pure returns (uint) {
    uint i = 0;
    for (uint8 j=0; j<encodedUint.length; j++) {
      i <<= 8;
  	i |= uint(encodedUint[j]);
    }
  	return i;
  }

  // helper func
  function asn1_read_length(bytes der, uint ix) private pure returns (NodePtr) {
  	uint first = uint(der[ix+1]);
    uint length;
    uint ix_first_content_byte;
    uint ix_last_content_byte;
  	if ((der[ix+1] & 0x80) == 0) {
  		length = first;
  		ix_first_content_byte = ix+2;
  		ix_last_content_byte = ix_first_content_byte + length -1;
    } else {  // -------------------- not thoroughly tested!! ------------------
      uint lengthbytesLength = first & 0x7F;
      bytes memory lengthbytes = new bytes(lengthbytesLength);
      for (uint i=0; i<lengthbytesLength; i++) {
          lengthbytes[i] = der[ix+2 + i];
      }
  		length = decodeUint(lengthbytes);
  		ix_first_content_byte = ix+2+lengthbytesLength;
  		ix_last_content_byte = ix_first_content_byte + length -1;
    } // -----------------------------------------------------------------------
  	return NodePtr({ixs: ix, ixf: ix_first_content_byte, ixl: ix_last_content_byte});
  }
}
