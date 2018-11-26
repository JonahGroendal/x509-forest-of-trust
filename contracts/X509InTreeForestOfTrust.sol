pragma solidity  ^0.4.25;

import "asn1-decode/contracts/Asn1Decode.sol";
import "sig-verify-algs/contracts/Algorithm.sol";
import "ens-solidity-namehash/contracts/NameHash.sol";
import "ethereum-datetime/contracts/DateTime.sol";

contract X509InTreeForestOfTrust {
  using Asn1Decode for bytes;
  using NameHash for string;

  constructor(address sha256WithRSAEncryption, address _dateTime) public {
    algs[keccak256('\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b')] = Algorithm(sha256WithRSAEncryption);
    dateTime = DateTime(_dateTime);
    cshxOidHash = keccak256("\x55\x1d\x13"); // change to actual oid of canSignHttpExchanges
  }

  DateTime dateTime;

  struct Certificate {
    address owner;
    bytes32 parentCert;
    bytes pubKey;
    uint serialNumber;
    uint validNotAfter;
    bool canSignHttpExchanges;
  }
  mapping (bytes32 => Certificate) public certs;
  mapping (bytes32 => bytes32) public certIds;
  mapping (bytes32 => bytes32[]) public certIdsLists;
  mapping(bytes32 => Algorithm) private algs;
  bytes32 private cshxOidHash;

  event CertificateAdded(bytes32 certId);
  event CertificateClaimed(bytes32 certId);


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
   * @param tbsCert The entire tbsCertificate node of the der-encoded
   *        X509 certificate.
   * @param signature The signed sha256 hash of (DER-encoded) tbsCertificate (signed with
   *        signersPubKey param). Should be found in same X509 cert as tbsCertificate
   * @param signersPubKey The DER-encoded node of the public key used to sign
   *        the signature param.
   */
  function addCertificate(bytes cert, bytes signersPubKey, bool canSignHttpExchanges)
  public returns (bool)
  {
    bytes32 certId;
    uint serialNumber;
    uint validNotAfter;
    uint node1;
    uint node2;
    uint node3;

    node1 = cert.root();
    node1 = cert.firstChildOf(node1);
    node2 = cert.firstChildOf(node1);
    node2 = cert.firstChildOf(node2);
    node2 = cert.nextSiblingOf(node2);
    // Extract serial number
    serialNumber = cert.uintAt(node2);

    node2 = cert.nextSiblingOf(node2);
    node2 = cert.firstChildOf(node2);
    node3 = cert.nextSiblingOf(node1);
    node3 = cert.nextSiblingOf(node3);
    // Verify signature
    require( algs[keccak256(cert.bytesAt(node2))].verify(signersPubKey, cert.allBytesAt(node1), cert.bytesAt(node3)), "Signature doesnt match");

    node1 = cert.firstChildOf(node1);
    node1 = cert.firstChildOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);
    node1 = cert.nextSiblingOf(node1);

    node2 = cert.firstChildOf(node1);
    require(toTimestamp(cert.bytesAt(node2)) <= now, "Invalid cert");
    node2 = cert.nextSiblingOf(node2);
    validNotAfter = toTimestamp(cert.bytesAt(node2));
    require(now <= validNotAfter, "Invalid cert");

    node1 = cert.nextSiblingOf(node1);
    node2 = cert.nextSiblingOf(node1);
    // Extract public key and calculate certId from it
    certId = keccak256(cert.allBytesAt(node2));

    node2 = cert.firstChildOf(node1);
    while (Asn1Decode.isChildOf(node2, node1)) {
      node3 = cert.firstChildOf(node2);
      node3 = cert.firstChildOf(node3);
      if ( keccak256(cert.bytesAt(node3)) == keccak256("\x55\x04\x03") ) {
        node3 = cert.nextSiblingOf(node3);
        certIdsLists[string(cert.bytesAt(node3)).namehash()].push(certId);
        break;
      }
      node2 = cert.nextSiblingOf(node2);
    }

    node1 = cert.nextSiblingOf(node1);

    // Add certificate to certs mapping
    certs[certId].pubKey = cert.allBytesAt(node1);
    certs[certId].parentCert = keccak256(signersPubKey);
    certs[certId].serialNumber = serialNumber;
    certs[certId].validNotAfter = validNotAfter;

    // Add reference from sha256 fingerprint
    certIds[sha256(cert)] = certId;

    if (canSignHttpExchanges) {
      node1 = cert.nextSiblingOf(node1);
      node1 = cert.firstChildOf(node1);
      node2 = cert.firstChildOf(node1);
      while (Asn1Decode.isChildOf(node2, node1)) {
        node3 = cert.firstChildOf(node2);
        if ( keccak256(cert.bytesAt(node3)) == cshxOidHash ) {
          certs[certId].canSignHttpExchanges = true;
          break;
        }
        node2 = cert.nextSiblingOf(node2);
      }
    }

    // Fire event
    emit CertificateAdded(certId);
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
  function signThis()
  external view returns (bytes32, uint)
  {
    return ( keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1))), block.number -1 );
  }

  /**
   * An eth account calls this method to prove ownership of a certificate in
   * certs mapping. If successful, certs[certId].owner will
   * be set to the caller's address. To change owner of a cert, this method must
   *  be called from the new desired owner address.
   *
   * @param certId The keccak256 hash of target certificate's public key
   * @param signature The SHA256 RSA signature of signThis()[0]
   * @param blockNumber The value of signThis()[1] (must be >= block.number - 5760)
   */
  function proveOwnership(bytes32 certId, bytes signature, uint blockNumber, bytes32 sigAlgHash)
  external returns (bool)
  {
    bytes memory message;
    // Only accept proof if it's less than about one day old (at 15sec/block)
    require( block.number - blockNumber <= 5760 );
    // Verify signature, which proves ownership
    message = abi.encodePacked(keccak256(abi.encodePacked(msg.sender, blockhash(blockNumber))));
    require( algs[sigAlgHash].verify(certs[certId].pubKey, message, signature) );

    certs[certId].owner = msg.sender;

    emit CertificateClaimed(certId);
  }

  function toTimestamp(bytes x509Time)
  private view returns (uint)
  {
    uint16 yrs;  uint8 mnths;
    uint8  dys;  uint8 hrs;
    uint8  mins; uint8 secs;
    uint8  offset;

    if (x509Time.length == 13) {
      if (uint16(x509Time[0])-48 < 5) yrs += 2000;
      else yrs += 1900;
    }
    else {
      yrs += (uint16(x509Time[0])-48) * 1000 + (uint16(x509Time[1])-48) * 100;
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

  /* function owner(bytes32 certId) public view returns (address) {
    return certs[certId].owner;
  }
  function parentCert(bytes32 certId) public view returns (bytes32) {
    return certs[certId].parentCert;
  }
  function pubKey(bytes32 certId) public view returns (bytes) {
    return certs[certId].pubKey;
  }
  function serialNumber(bytes32 certId) public view returns (uint) {
    return certs[certId].serialNumber;
  }
  function validNotAfter(bytes32 certId) public view returns (uint) {
    return certs[certId].validNotAfter;
  }
  function canSignHttpExchanges(bytes32 certId) public view returns (bool) {
    return certs[certId].canSignHttpExchanges;
  } */
}
