pragma solidity  ^0.5.2;

import "./Ownable.sol";
import "asn1-decode/contracts/Asn1Decode.sol";
//import "solidity-bytes-utils/contracts/BytesUtils.sol";
import "sig-verify-algs/contracts/Algorithm.sol";
import "ens-namehash/contracts/ENSNamehash.sol";
import "ethereum-datetime/contracts/DateTime.sol";

/*
 * @dev Stores validated X.509 certificate chains in parent pointer trees.
 * @dev The root of each tree is a CA root certificate
 */
contract X509ForestOfTrust is Ownable {
  using Asn1Decode for bytes;
  using ENSNamehash for bytes;

  bytes10 constant private OID_SUBJECT_ALT_NAME   = 0x551d1100000000000000;
  bytes10 constant private OID_BASIC_CONSTRAINTS  = 0x551d1300000000000000;
  bytes10 constant private OID_NAME_CONSTRAINTS   = 0x551d1e00000000000000;
  bytes10 constant private OID_KEY_USAGE          = 0x551d0f00000000000000;
  bytes10 constant private OID_EXTENDED_KEY_USAGE = 0x551d2500000000000000;
  bytes10 private OID_CAN_SIGN_HTTP_EXCHANGES     = 0x2b06010401d679020116; // Not constant because spec may change

  constructor(address sha256WithRSAEncryption, address _dateTime) public {
    bytes32 algOid = 0x2a864886f70d01010b0000000000000000000000000000000000000000000000;
    algs[algOid] = Algorithm(sha256WithRSAEncryption);
    dateTime = DateTime(_dateTime);
  }

  struct Certificate {
    address owner;
    bytes32 parentId;
    uint40 timestamp;
    uint160 serialNumber;
    uint40 validNotBefore;
    uint40 validNotAfter;
    bool cA;                        // Whether the certified public key may be used to verify certificate signatures.
    uint8 pathLenConstraint;        // Maximum number of non-self-issued intermediate certs that may follow this
                                    // cert in a valid certification path.
    bool keyUsagePresent;
    uint16 keyUsage;                // Value of KeyUsage bits. (E.g. 000000101 is 5)
    bool extKeyUsagePresent;
    bytes32[] extKeyUsage;
    bool sxg;                       // canSignHttpExchanges extension is present.
    bool uncheckedCriticalExtension;// If true, further validation is needed. Use extId to save gas.
    bytes32 extId;                  // keccak256 of extensions field for further validation.
  }

  mapping (bytes32 => Certificate) public  certs;     // certId => cert  (certId is keccak256(pubKey))
  mapping (bytes32 => Algorithm)   private algs;      // algorithm oid bytes => signature verification contract
  mapping (bytes32 => bytes32[])   public  toCertIds; // ensNamehash(subjectAltName) => certId
  mapping (bytes32 => bytes32)     public  toCertId;  // sha256 fingerprint => certId
  DateTime dateTime;                                  // For dateTime conversion

  event CertAdded(bytes32);
  event CertClaimed(bytes32);
  event AlgSet(bytes32, address);

  /**
   * @dev Add a X.509 certificate to an existing tree/chain
   * @param cert A DER-encoded X.509 certificate
   * @param parentPubKey The parent certificate's DER-encoded public key
   */
  function addCert(bytes memory cert, bytes memory parentPubKey)
  public
  {
    Certificate memory certificate;
    bytes32 certId;
    uint node1;
    uint node2;
    uint node3;
    uint node4;

    certificate.parentId = keccak256(parentPubKey);
    certificate.timestamp = uint40(block.timestamp);

    node1 = cert.root();
    node1 = cert.firstChildOf(node1);
    node2 = cert.firstChildOf(node1);
    if (cert[NodePtr.ixs(node2)] == 0xa0) {
      node2 = cert.nextSiblingOf(node2);
    }
    // Extract serial number
    certificate.serialNumber = uint160(cert.uintAt(node2));

    node2 = cert.nextSiblingOf(node2);
    node2 = cert.firstChildOf(node2);
    node3 = cert.nextSiblingOf(node1);
    node3 = cert.nextSiblingOf(node3);
    // Verify signature
    require(algs[cert.bytes32At(node2)].verify(parentPubKey, cert.allBytesAt(node1), cert.bytesAt(node3)), "Signature doesnt match");

    node1 = cert.firstChildOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);

    node2 = cert.firstChildOf(node1);
    // Check validNotBefore
    certificate.validNotBefore = uint40(toTimestamp(cert.bytesAt(node2)));
    require(certificate.validNotBefore <= now, "Now is before validNotBefore");
    node2 = cert.nextSiblingOf(node2);
    // Check validNotAfter
    certificate.validNotAfter = uint40(toTimestamp(cert.bytesAt(node2)));
    require(now <= certificate.validNotAfter, "Now is after validNotAfter");

    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);
    // Get public key and calculate certId from it
    certId = cert.keccakOfAllBytesAt(node1);
    // Fire event
    emit CertAdded(certId);

    // Add reference from sha256 fingerprint
    toCertId[sha256(cert)] = certId;

    node1 = cert.nextSiblingOf(node1);

    // Skip over v2 fields
    if (cert[NodePtr.ixs(node1)] == 0xa1)
      node1 = cert.nextSiblingOf(node1);
    if (cert[NodePtr.ixs(node1)] == 0xa2)
      node1 = cert.nextSiblingOf(node1);

    // Parse extensions
    if (cert[NodePtr.ixs(node1)] == 0xa3) {
      // Save hash of extensions
      certificate.extId = cert.keccakOfAllBytesAt(node1);
      node1 = cert.firstChildOf(node1);
      node2 = cert.firstChildOf(node1);
      bytes10 oid;
      bool isCritical;
      while (Asn1Decode.isChildOf(node2, node1)) {
        node3 = cert.firstChildOf(node2);
        oid = bytes10(cert.bytes32At(node3)); // Extension oid
        node3 = cert.nextSiblingOf(node3);
        // Check if extension is critical
        if (cert[NodePtr.ixs(node3)] == 0x01) { // If type is bool
          if (cert[NodePtr.ixf(node3)] != 0x00) // If not false
            isCritical = true;
          node3 = cert.nextSiblingOf(node3);
        }
        if (oid == OID_SUBJECT_ALT_NAME) {
          // Add references from names
          node3 = cert.rootOfOctetStringAt(node3);
          node4 = cert.firstChildOf(node3);
          while (Asn1Decode.isChildOf(node4, node3)) {
            if(cert[NodePtr.ixs(node4)] == 0x82)
              toCertIds[cert.bytesAt(node4).namehash()].push(certId);
            else
              toCertIds[cert.keccakOfBytesAt(node4)].push(certId);
            node4 = cert.nextSiblingOf(node4);
          }
        }
        else if (oid == OID_BASIC_CONSTRAINTS && isCritical) {
          // Check if cert can sign other certs
          node3 = cert.rootOfOctetStringAt(node3);
          node4 = cert.firstChildOf(node3);
          // If sequence (node3) is not empty
          if (Asn1Decode.isChildOf(node4, node3)) {
            // If value == true
            if (cert[NodePtr.ixf(node4)] != 0x00) {
              certificate.cA = true;
              node4 = cert.nextSiblingOf(node4);
              if (Asn1Decode.isChildOf(node4, node3)) {
                certificate.pathLenConstraint = uint8(cert.uintAt(node4));
              }
              else {
                certificate.pathLenConstraint = uint8(-1);
              }
            }
          }
        }
        else if (oid == OID_KEY_USAGE) {
          certificate.keyUsagePresent = true;
          node3 = cert.rootOfOctetStringAt(node3);
          bytes3 v = bytes3(cert.bytes32At(node3)); // The encoded bitstring value
          certificate.keyUsage = ((uint16(uint8(v[1])) << 8) + uint16(uint8(v[2]))) >> 7;
        }
        else if (oid == OID_EXTENDED_KEY_USAGE) {
          certificate.extKeyUsagePresent = true;
          node3 = cert.rootOfOctetStringAt(node3);
          node4 = cert.firstChildOf(node3);
          uint len;
          while (Asn1Decode.isChildOf(node4, node3)) {
            len++;
            node4 = cert.nextSiblingOf(node4);
          }
          bytes32[] memory oids = new bytes32[](len);
          node4 = cert.firstChildOf(node3);
          for (uint i; i<len; i++) {
            oids[i] = cert.bytes32At(node4);
            node4 = cert.nextSiblingOf(node4);
          }
          certificate.extKeyUsage = oids;
        }
        else if (oid == OID_CAN_SIGN_HTTP_EXCHANGES) {
          certificate.sxg = true;
        }
        else if (oid == OID_NAME_CONSTRAINTS) {
          // Name constraints not allowed.
          require(false, "Name constraints extension not supported");
        }
        else if (isCritical) {
          // Note: unrecognized critical extensions are allowed.
          // Further validation of certificate is needed.
          certificate.uncheckedCriticalExtension = true;
        }
        node2 = cert.nextSiblingOf(node2);
      }
    }

    certs[certId] = certificate;

    require(certs[certificate.parentId].cA, "Invalid parent cert");

    // If intermediate cert, verify authority's pathLenConstraint
    if (certificate.cA && certId != certificate.parentId)
      require(certs[certificate.parentId].pathLenConstraint == uint8(-1) || certs[certificate.parentId].pathLenConstraint > certificate.pathLenConstraint, "Invalid parent cert");
    // RFC 5280: If the cA boolean is not asserted, then the keyCertSign
    // bit in the key usage extension MUST NOT be asserted.
    if (!certificate.cA)
      require(certificate.keyUsage & 8 != 8, "cA boolean is not asserted and keyCertSign bit is asserted");
  }

  /**
   * @dev The return values of this function are used to proveOwnership() of a
   *      certificate that exists in the certs mapping.
   * @return Some unique bytes to be signed
   * @return The block number used to create the first return value
   */
  function signThis()
  external view returns (bytes memory, uint)
  {
    return ( abi.encodePacked(msg.sender, blockhash(block.number - 1)), block.number -1 );
  }

  /**
   * @dev An account calls this method to prove ownership of a certificate.
   *      If successful, certs[certId].owner will be set to caller's address.
   * @param pubKey The target certificate's public key
   * @param signature signThis()[0] signed with certificate's private key
   * @param blockNumber The value of signThis()[1] (must be > block.number - 256)
   * @param sigAlg The OID of the algorithm used to sign `signature`
   */
  function proveOwnership(bytes calldata pubKey, bytes calldata signature, uint blockNumber, bytes32 sigAlg)
  external returns (bool)
  {
    bytes32 certId = keccak256(pubKey);
    bytes memory message = abi.encodePacked(msg.sender, blockhash(blockNumber));

    emit CertClaimed(certId);

    // Only accept proof if it's less than 256 blocks old
    // This is the most time I can give since blockhash() can only return the 256 most recent
    require(block.number - blockNumber < 256, "Signature too old");
    // Verify signature, which proves ownership
    require(algs[sigAlg].verify(pubKey, message, signature), "Signature doesnt match");

    certs[certId].owner = msg.sender;
  }

  function rootOf(bytes32 certId)external view returns (bytes32) {
    bytes32 id = certId;
    while (id != certs[id].parentId) {
      id = certs[id].parentId;
    }
    return id;
  }

  function owner(bytes32 certId) external view returns (address) {
    return certs[certId].owner;
  }

  function parentId(bytes32 certId) external view returns (bytes32) {
    return certs[certId].parentId;
  }

  function serialNumber(bytes32 certId) external view returns (uint160) {
    return certs[certId].serialNumber;
  }

  function timestamp(bytes32 certId) external view returns (uint40) {
    return certs[certId].timestamp;
  }

  function validNotBefore(bytes32 certId) external view returns (uint40) {
    return certs[certId].validNotBefore;
  }

  function validNotAfter(bytes32 certId) external view returns (uint40) {
    return certs[certId].validNotAfter;
  }

  function sxg(bytes32 certId) external view returns (bool) {
    return certs[certId].sxg;
  }

  function pathLenConstraint(bytes32 certId) external view returns (uint8) {
    return certs[certId].pathLenConstraint;
  }

  function cA(bytes32 certId) external view returns (bool) {
    return certs[certId].cA;
  }

  function keyUsage(bytes32 certId) external view returns (bool, bool[9] memory) {
    uint16 mask = 256;
    bool[9] memory flags;
    uint16 bits = certs[certId].keyUsage;
    bool isPresent = certs[certId].keyUsagePresent;
    if (isPresent) {
      for (uint i; i<9; i++) {
        flags[i] = (bits & mask == mask);
        mask = mask >> 1;
      }
    }
    return (isPresent, flags);
  }

  function extKeyUsage(bytes32 certId) external view returns (bool, bytes32[] memory) {
    return (certs[certId].extKeyUsagePresent, certs[certId].extKeyUsage);
  }

  function uncheckedCriticalExtension(bytes32 certId) external view returns (bool) {
    return certs[certId].uncheckedCriticalExtension;
  }

  function extId(bytes32 certId) external view returns (bytes32) {
    return certs[certId].extId;
  }

  function toCertIdsLength(bytes32 _hash) external view returns (uint) {
    return toCertIds[_hash].length;
  }

  function toTimestamp(bytes memory x509Time) private view returns (uint) {
    uint16 yrs;  uint8 mnths;
    uint8  dys;  uint8 hrs;
    uint8  mins; uint8 secs;
    uint8  offset;

    if (x509Time.length == 13) {
      if (uint8(x509Time[0])-48 < 5) yrs += 2000;
      else yrs += 1900;
    }
    else {
      yrs += (uint8(x509Time[0])-48) * 1000 + (uint8(x509Time[1])-48) * 100;
      offset = 2;
    }
    yrs +=  (uint8(x509Time[offset+0])-48)*10 + uint8(x509Time[offset+1])-48;
    mnths = (uint8(x509Time[offset+2])-48)*10 + uint8(x509Time[offset+3])-48;
    dys +=  (uint8(x509Time[offset+4])-48)*10 + uint8(x509Time[offset+5])-48;
    hrs +=  (uint8(x509Time[offset+6])-48)*10 + uint8(x509Time[offset+7])-48;
    mins += (uint8(x509Time[offset+8])-48)*10 + uint8(x509Time[offset+9])-48;
    secs += (uint8(x509Time[offset+10])-48)*10 + uint8(x509Time[offset+11])-48;

    return dateTime.toTimestamp(yrs, mnths, dys, hrs, mins, secs);
  }

  function setAlg(bytes32 oid, address alg) external onlyOwner {
    algs[oid] = Algorithm(alg);
    emit AlgSet(oid, alg);
  }

  function setSxgOid(bytes32 sxgOid) external onlyOwner {
    OID_CAN_SIGN_HTTP_EXCHANGES = bytes10(sxgOid);
  }
}
