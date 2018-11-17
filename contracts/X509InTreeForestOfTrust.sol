pragma solidity  ^0.4.25;
pragma experimental ABIEncoderV2;

import "asn1-decode/contracts/Asn1Decode.sol";
import "pkcs1-sha256-verify/contracts/Pkcs1Sha256Verify.sol";

contract X509InTreeForestOfTrust {
  constructor(address decoderAddr, address verifierAddr) {
    decoder = Asn1Decode(decoderAddr);
    verifier = Pkcs1Sha256Verify(verifierAddr);
  }

  Asn1Decode decoder;
  Pkcs1Sha256Verify verifier;

  struct Certificate {
    address owner;
    bytes32 ens;
    bytes32 revokedBy;
    bytes32 parent;
    bytes tbsCertificate;
    bytes signature;
    uint validNotBefore;
    uint validNotAfter;
  }
  mapping (bytes32 => Certificate) private certificates;
  mapping (bytes32 => bytes32[]) private certificateIdsReference;
  bytes32[] private serialNumbers;

  event certificateAdded(bytes32 certificateId);
  event certificateClaimed(bytes32 certificateId);


  /* TODO add function to set certificate
  function rovokeCertificate(bytes certificateRevocation, bytes signature, bytes32 authorityCertificateId)
  /*
   * NOTICE: This function is currently unfinished. Needs to extract
   * validNotBefore and validNotAfter and initialize the certificate with those
   * values too!! (shouldn't take much work).
   *
   * Adds a X509 certificate to the certificates mapping, which is indexed on
   * certificateId (the keccak256 hash of its public key). Anyone can call this
   * method so long as they have the funds to cover the transaction. The
   * certificate must be signed and valid (but not nessisarily by any existing
   * certificates in the mapping). Certificates may be self-signed. The idea is
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
  function addCertificate(bytes tbsCertificate, bytes signature, bytes signersPubKey) public returns (bool){
    bytes32 certificateId;
    bytes32 serialNumber;
    string memory commonName;
    bytes memory modulus;
    bytes memory exponent;
    Asn1Decode.NodePtr memory i;
    Asn1Decode.NodePtr memory j;
    Asn1Decode.NodePtr memory k;

    // Extract modulus and exponent from signersPubKey
    (modulus, exponent) = extractRsaPubKeyComponents(signersPubKey);

    // Verify signature
    require( verifier.verify(sha256(tbsCertificate), signature, exponent, modulus) == 0 );

    // Extract serial number from tbsCertificate
    i = decoder.nodeTraverse(tbsCertificate, decoder.LOCATION_SERIAL_NUMBER());
    serialNumber = bytes32(decoder.decodeUint(decoder.getValue(tbsCertificate, i)));

    i = decoder.nodeNext(tbsCertificate, i);
    i = decoder.nodeNext(tbsCertificate, i);
    i = decoder.nodeNext(tbsCertificate, i);
    j = decoder.nodeFirstChild(tbsCertificate, i);
    // get validNotBefore
    j = decoder.nodeNext(tbsCertificate, j);
    // get validNotAfter

    i = decoder.nodeNext(tbsCertificate, i);
    j = decoder.nodeFirstChild(tbsCertificate, i);
    while (decoder.nodeIsChildOf(j, i)) {
      k = decoder.nodeFirstChild(tbsCertificate, j);
      k = decoder.nodeFirstChild(tbsCertificate, k);
      if ( keccak256(decoder.getValue(tbsCertificate, k)) == keccak256(decoder.COMMON_NAME()) ) {
        k = decoder.nodeNext(tbsCertificate, k);
        commonName = string(decoder.getValue(tbsCertificate, k)); // Make sure this translates from bytes to string correctly
        break;
      }
      j = decoder.nodeNext(tbsCertificate, j);
    }

    i = decoder.nodeNext(tbsCertificate, i);
    // Extract public key and calculate certificateId from it
    certificateId = keccak256(decoder.getAll(tbsCertificate, i));

    // Revoked certificates may not be written over
    require( certificates[certificateId].revokedBy == 0 );

    // Add certificate to certificates mapping
    certificates[certificateId].parent = keccak256(signersPubKey);
    certificates[certificateId].tbsCertificate = tbsCertificate;
    certificates[certificateId].signature = signature;

    // Add serial number to serialNumbers array and certificateIdsReference mapping
    serialNumbers.push(serialNumber);
    certificateIdsReference[keccak256(serialNumber)].push(certificateId);

    // Fire event
    certificateAdded(certificateId);
  }

  /*
   * Adds a reference to certificateIdsReference mapping. Reference must go to a
   * certificateId of an existing certificate. The reference (the key) is from
   * the keccak256 hash of the node at keyLocation of certificates[certificateId]
   * to certificateId.
   *
   * @param certifiacateId The certificateId to which we are adding a reference.
   *        (must be the certificateId of a certificate in certificates mapping)
   * @param keyLocation The traversal instructions for the desired node from which
   *        the reference key is derived. Same encoding as "location" param in
   *        nodeTraverse() function.
   */
  function addReference(bytes32 certificateId, bytes keyLocation) public {
    Asn1Decode.NodePtr memory i;
    bytes memory v;

    i = decoder.nodeTraverse(certificates[certificateId].tbsCertificate, keyLocation);
    v = decoder.getValue(certificates[certificateId].tbsCertificate, i);
    certificateIdsReference[keccak256(v)].push(certificateId);
  }

  /**
   * The return values of this function are used to proveOwnership() of a
   * certificate that exists in the certificates mapping.

   * @return A unique keccak256 hash to be signed
   * @return The block number used in the hash
   */
  function signThis() public view returns (bytes32, uint) {
    return ( keccak256(msg.sender, block.blockhash(block.number - 1)), block.number -1 );
  }

  /**
   * An eth account calls this method to prove ownership of a certificate in
   * certificates mapping. If successful, certificates[certificateId].owner will
   * be set to the caller's address. To change owner of a cert, this method must
   *  be called from the new desired owner address.
   *
   * @param certificateId The keccak256 hash of target certificate's public key
   * @param signature The PKS1 RSA signature of the first return value of signThis()
   * @param blockNumber The second return value of signThis() (must be >= block.number - 5760)
   */
  function proveOwnership(bytes32 certificateId, bytes signature, uint blockNumber) external returns (bool){
    bytes32 message;
    bytes memory pubKey;
    bytes memory modulus;
    bytes memory exponent;
    Asn1Decode.NodePtr memory i;

    // Only accept proof if it's less than about one day old (at 15sec/block)
    require( block.number - blockNumber <= 5760 );

    // Verify signature, which proves ownership
    message = keccak256(msg.sender, block.blockhash(blockNumber));
    i = decoder.nodeTraverse(certificates[certificateId].tbsCertificate, decoder.LOCATION_PUB_KEY());
    pubKey = decoder.getAll(certificates[certificateId].tbsCertificate, i);
    (modulus, exponent) = extractRsaPubKeyComponents(pubKey);
    require( verifier.verify(sha256(message), signature, exponent, modulus) == 0 );

    certificates[certificateId].owner = msg.sender;

    certificateClaimed(certificateId);
  }

  /**
   * Extracts modulus and exponent (respectively) from a DER-encoded RSA public key
   *
   * Helper function
   */
  function extractRsaPubKeyComponents(bytes key) private view returns (bytes, bytes) {
    bytes memory modulus;
    bytes memory exponent;
    bytes memory encodedModulus;
    bytes memory encodedExponent;
    bytes memory encodedBytes;
    Asn1Decode.NodePtr memory i;

    i = decoder.nodeRoot(key);
    i = decoder.nodeFirstChild(key, i);
    i = decoder.nodeNext(key, i);
    // Decode bitstring
    encodedBytes = decoder.getValue(key, i);
    for (uint j=0; j<encodedBytes.length-1; j++) {
      encodedBytes[j] = encodedBytes[j+1];
    }
    i = decoder.nodeRoot(encodedBytes);
    i = decoder.nodeFirstChild(encodedBytes, i);
    encodedModulus = decoder.getValue(encodedBytes, i);
    // modulus must be positive
    require( encodedModulus[0] & 0x80 == 0 );
    // remove leading zero byte from der encoding of modulus if present
    if (encodedModulus[0] == 0) {
       modulus = new bytes(encodedModulus.length - 1);
       for (uint index=0; index<modulus.length; index++) {
           modulus[index] = encodedModulus[index+1];
       }
    } else {
       modulus = encodedModulus;
    }
    i = decoder.nodeNext(encodedBytes, i);
    encodedExponent = decoder.getValue(encodedBytes, i);
    // exponent must be positive
    require( encodedExponent[0] & 0x80 == 0 );
    // remove leading zero byte from der encoding of exponent if present
    if (encodedExponent[0] == 0) {
       exponent = new bytes(encodedExponent.length - 1);
       for (index=0; index<exponent.length; index++) {
           exponent[index] = encodedExponent[index+1];
       }
    } else {
       exponent = encodedExponent;
    }

    return (modulus, exponent);
  }

  function ensNameHash(bytes memory name) private pure returns (bytes32) {
    bytes memory prefix;
    bytes memory rest;
    bytes32 zeroBytes;
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

    return keccak256(ensNameHash(rest), keccak256(prefix));
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
  function certificate(bytes32 certificateId) public view returns (Certificate) {
    return certificates[certificateId];
  }

  // For testing. Also, make sure the new web3 can handle structs (unlike the old)
  function tbsCertificate(bytes32 certificateId) public view returns (bytes) {
    return certificates[certificateId].tbsCertificate;
  }

  function certificateId(bytes32 referenceHash) public view returns (bytes32[]) {
    return certificateIdsReference[referenceHash];
  }
}
