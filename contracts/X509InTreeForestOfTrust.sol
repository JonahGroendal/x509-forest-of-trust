pragma solidity  ^0.4.25;

import "asn1-decode/contracts/Asn1Decode.sol";
import "sig-verify-algs/contracts/Algorithm.sol";

contract X509InTreeForestOfTrust {
  using Asn1Decode for uint;

  struct Certificate {
    address verifiedBy;
    address owner;
    bytes32 ens;
    bytes32 revokedBy;
    bytes32 parent;
    bytes pubKey;
    bytes tbsCertificate;
    bytes signature;
    uint validNotBefore;
    uint validNotAfter;
    bool canSignHttpExchanges;
  }
  mapping (bytes32 => Certificate) private certs;
  mapping (bytes32 => bytes32[]) private certIds;

  event CertificateAdded(bytes32 certId, bytes32 sn);
  event CertificateClaimed(bytes32 certId);

  bytes constant public COMMON_NAME = "\x55\x04\x03";
  // shortcuts to commonly used X509 nodes
  bytes constant public LOCATION_SERIAL_NUMBER = '\x00\x02\x01';
  bytes constant public LOCATION_PUB_KEY = '\x00\x02\x06';
  bytes constant public LOCATION_VALID_NOT_BEFORE = '\x00\x02\x04\x01';
  bytes constant public LOCATION_VALID_NOT_AFTER = '\x00\x02\x04\x01\x01';


  /* TODO add function to set certificate
  function rovokeCertificate(bytes certificateRevocation, bytes signature, bytes32 authorityCertificateId)
  /*
   * NOTICE: This function is currently unfinished. Needs to extract
   * validNotBefore and validNotAfter and initialize the certificate with those
   * values too!! (shouldn't take much work).
   *
   * Adds a X509 certificate to the certs mapping, which is indexed on
   * certId (the keccak256 hash of its public key). Anyone can call this
   * method so long as they have the funds to cover the transaction. The
   * certificate must be signed and valid (but not nessisarily by any existing
   * certs in the mapping). Certificates may be self-signed. The idea is
   * to pulicise a verified chain of trust on the blockchain that can be
   * referenced by other contracts.
   *
   * @param tbsCertificate The entire tbsCertificate node of the der-encoded
   *        X509 certificate.
   * @param signature The signed sha256 hash of (DER-encoded) tbsCertificate (signed with
   *        signersPubKey param). Should be found in same X509 cert as tbsCertificate
   * @param signersPubKey The DER-encoded node of the public key used to sign
   *        the signature param.
   */
  function addCertificate(bytes tbsCertificate, bytes signature, bytes signersPubKey, address verifier) public returns (bool){
    bytes32 certId;
    bytes32 serialNumber;
    bytes memory commonName;
    uint node1;
    uint node2;
    uint node3;

    // Verify signature
    require( Algorithm(verifier).verify(signersPubKey, tbsCertificate, signature) );

    // Extract serial number from tbsCertificate
    node1 = Asn1Decode.traverse(tbsCertificate, LOCATION_SERIAL_NUMBER);
    serialNumber = bytes32(Asn1Decode.decodeUint(node1.getValue(tbsCertificate)));

    node1 = node1.next(tbsCertificate);
    node1 = node1.next(tbsCertificate);
    node1 = node1.next(tbsCertificate);
    node2 = node1.firstChild(tbsCertificate);
    // get validNotBefore
    node2 = node2.next(tbsCertificate);
    // get validNotAfter

    node1 = node1.next(tbsCertificate);
    node2 = node1.firstChild(tbsCertificate);
    while (node2.isChildOf(node1)) {
      node3 = node2.firstChild(tbsCertificate);
      node3 = node3.firstChild(tbsCertificate);
      if ( keccak256(node3.getValue(tbsCertificate)) == keccak256(COMMON_NAME) ) {
        node3 = node3.next(tbsCertificate);
        commonName = node3.getValue(tbsCertificate); // Make sure this translates from bytes to string correctly
        break;
      }
      node2 = node2.next(tbsCertificate);
    }

    node1 = node1.next(tbsCertificate);
    // Extract public key and calculate certId from it
    certId = keccak256(node1.getAll(tbsCertificate));

    // Revoked certs may not be written over
    require( certs[certId].revokedBy == 0 );

    // Add certificate to certs mapping
    certs[certId].pubKey = node1.getAll(tbsCertificate);
    certs[certId].verifiedBy = verifier;
    certs[certId].parent = keccak256(signersPubKey);

    // Add common name to certIds mapping
    certIds[keccak256(commonName)].push(certId);

    // Fire event
    emit CertificateAdded(certId, serialNumber);
  }

  /*
   * Adds a reference to certIds mapping. Reference must go to a
   * certId of an existing certificate. The reference (the key) is from
   * the keccak256 hash of the node at keyLocation of certs[certId]
   * to certId.
   *
   * @param certifiacateId The certId to which we are adding a reference.
   *        (must be the certId of a certificate in certs mapping)
   * @param keyLocation The traversal instructions for the desired node from which
   *        the reference key is derived. Same encoding as "location" param in
   *        traverse() function.
   */
  /* function addReference(bytes32 certId, bytes keyLocation) public {
    uint node;
    bytes memory v;

    node = Asn1Decode.traverse(certs[certId].tbsCertificate, keyLocation);
    v = node.getValue(certs[certId].tbsCertificate);
    certIds[keccak256(v)].push(certId);
  } */

  /**
   * The return values of this function are used to proveOwnership() of a
   * certificate that exists in the certs mapping.

   * @return A unique keccak256 hash to be signed
   * @return The block number used in the hash
   */
  function signThis() external view returns (bytes32, uint) {
    return ( keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1))), block.number -1 );
  }

  /**
   * An eth account calls this method to prove ownership of a certificate in
   * certs mapping. If successful, certs[certId].owner will
   * be set to the caller's address. To change owner of a cert, this method must
   *  be called from the new desired owner address.
   *
   * @param certId The keccak256 hash of target certificate's public key
   * @param signature The RSA signature of the first return value of signThis()
   * @param blockNumber The second return value of signThis() (must be >= block.number - 5760)
   */
  function proveOwnership(bytes32 certId, bytes signature, uint blockNumber) external returns (bool){
    bytes memory message;

    // Only accept proof if it's less than about one day old (at 15sec/block)
    require( block.number - blockNumber <= 5760 );

    // Verify signature, which proves ownership
    message = abi.encodePacked(keccak256(abi.encodePacked(msg.sender, blockhash(blockNumber))));
    require( Algorithm(certs[certId].verifiedBy).verify(certs[certId].pubKey, message, signature) );

    certs[certId].owner = msg.sender;

    emit CertificateClaimed(certId);
  }

  function ensNameHash(bytes memory name) private pure returns (bytes32) {
    bytes memory prefix;
    bytes memory rest;
    uint8 i;
    uint8 j;

    // base case
    if (name.length == 0) { return 0x0000000000000000000000000000000000000000000000000000000000000000; }

    // Find index of delimiter
    while(name[i] != "." && i < name.length) {
      i++;
    }

    prefix = new bytes(i);
    if (i >= name.length) {
      rest = new bytes(0);
    } else {
      rest = new bytes(name.length-1 - i);
    }

    for(j=0; j<i; j++) {
      prefix[j] = name[j];
    }
    if (i < name.length) {
      for(j=0; j<name.length-1 - i; j++) {
        rest[j] = name[i+1 + j];
      }
    }

    return keccak256(abi.encodePacked(ensNameHash(rest), keccak256(prefix)));
  }

  /* not finished, hasnt been tested at all. most likely does not work in current state
  function decodeTime(bytes x509Time) internal pure returns (uint) {
    uint time;
    uint i;
    uint256[12] memory daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    uint offset = 0;

    // years
    if (x509Time.length == 13) {
      if (uint(x509Time[0]) < 5) {
        time += 2000;
      } else {
        time += 1900;
      }
    } else {
      time += uint(x509Time[0]) * 1000 + uint(x509Time[1]) * 100;
      offset = 2;
    }
    time += uint(x509Time[offset+0]) * 10 + uint(x509Time[offset+1]);
    // The year must be >= 1972 for the following calculations to work
    require( time >= 1972 );
    if (time % 4 == 0) daysInMonth[1]++;
    time -= 1970; // minus unix epoch year
    // months
    time *= 12;
    time += uint(x509Time[offset+2]) * 10 + uint(x509Time[offset+3]);
    //days
    time = 365 + 366 + ( (time/12-2)/4 * 366 + (((time/12-2) - (time/12-2)/4)) * 365 );
    for (i=0; i<uint(x509Time[offset+2])*10 + uint(x509Time[offset+3]); i++) { // for the number of months since January
      time += daysInMonth[i];
    }
    time += uint(x509Time[offset+4])*10 + uint(x509Time[offset+5]);
    // hours
    time *= 24;
    time += uint(x509Time[offset+6])*10 + uint(x509Time[offset+7]);
    // Minutes
    time *= 60;
    time += uint(x509Time[offset+8])*10 + uint(x509Time[offset+9]);
    // Seconds
    time *= 60;
    time += uint(x509Time[offset+10])*10 + uint(x509Time[offset+11]);

    ...return time in seconds since unix epoch

  }
  */
  /* function certificate(bytes32 certId) public view returns (Certificate) {
    return certs[certId];
  } */

  // For testing. Also, make sure the new web3 can handle structs (unlike the old)
  function tbsCertificate(bytes32 certId) public view returns (bytes) {
    return certs[certId].tbsCertificate;
  }

  function certId(bytes32 referenceHash) public view returns (bytes32[]) {
    return certIds[referenceHash];
  }
}
