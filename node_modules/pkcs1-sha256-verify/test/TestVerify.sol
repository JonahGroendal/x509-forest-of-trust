pragma solidity ^0.4.19;

import "truffle/Assert.sol";
import "truffle/DeployedAddresses.sol";
import "../contracts/Pkcs1Sha256Verify.sol";

contract TestVerify {
  function testPkcs1Sha256VerifySuccess() public {
    uint[4] memory s = [
        0x5f49d8dc4519d9520d6542eca08cafb2d99cdb97c5a8685df2476b40505a2f9e,
        0x8d63d76516b83481e2d961a7e8dc5f9f46887e394776711b0f85e4303065c06d,
        0x362456bc219fc6eb343ede6733f779f75853533bc9ab876188da8ad98f9ea2f3,
        0x35d2ceec34ef9cb2782bb0f79cad309608ddc222e00ebcff9d14f6e6ed39638b
    ];

    uint[1] memory e = [
        uint(0x10001)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0xf56379c42e3ba856585ca28f7fb768f65d273a5fc546156142857b0afb7c72d2,
        0xd97ecfceec71b4260bdc58c9bb42065f53af69805d9006233ec70a591aff463b,
        0xf23d78200fb8cc14a4eba286afe8924120efad9e3d3f06f7452c725e53728b8f,
        0x86c9fb245fbaf7086ab0092e215213830d1091212efc1ec59ddc3a83707d4ab8
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 0;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 0 indicating a valid signature");
  }
  function testPkcs1Sha256VerifyExponentChanged() public {
    uint[4] memory s = [
            0x0ac6e41252383ee5d07f4fb08a22204f56440a8f3c8568d6e6bae46cfc9d39b6,
            0x5b2eae827164d716e9e465301d08fca7356ef447e0699feabbfac16ed19dc923,
            0x3b457fe64d6fab38aca4464e5cd3eae3f43bab17856cdcc942e2cc848b7bf390,
            0xfc53b3ed2e6f63c5d961bc83475ac200708f6e1d5be30cbe24fe4d3dad754269
    ];

    uint[1] memory e = [
        uint(0x3)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0x9be28a4763c6665880c1c2a8a74494622be46de3c20e5b118cf70fee51d33b6d,
        0x0b473e84a4200382004526a33eea59e13b07070e580937207ec7b2cc5fb76856,
        0xfe6210a771150fa0e5da9baee4a6209ed3d4e2b3bfd2e5f6591b0ace3e657ad0,
        0x7c1b47d8520d5159386767f11fdfaf41fa3348fb7dd32d3c25da5d1d78433985
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 1;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 1");
  }
  function testPkcs1Sha256VerifySignatureChanged() public {
    uint[4] memory s = [
            0x750e59f29d2dfeedab2a3a09034904715957149126c63e6a2dc7a633a32c4c05,
            0x61d54eeb1479cb65274bac37cac4751f4dffdfb7530171599b61d94862845f6c,
            0xd12a5e0bd6adabc36f06d216a00b1942349710540555106aeb87f5cf3f78df91,
            0x8f36cf63291ef2a7064e31b84075d1c8b551225a25f59c721a3d77046078557f
    ];

    uint[1] memory e = [
        uint(0x10001)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0xa6ce108ff3100b953781496c3d081fe32b8cedaf6d14aab2ef2dc37d8f8d2613,
        0xd2f599efd55c51498749c0961681ae4ea7e28bf14a8f044c2d4dd4f9102ddd25,
        0xf86c7795289708eb4df2d526f91b176952eb52fd0c9de2989432d6e08e13022b,
        0x82f95089d20a5704f0452f26cd1f83bc956ee7da99876c1f8da3723af388bead
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 1;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 1");
  }
  function testPkcs1Sha256VerifyMessageChanged() public {
    uint[4] memory s = [
        0x8b5a3675f397841c53a9021dad71a1efab91451c71ad7060ce85d75b306d6403,
        0xba23d3370b0695be87485cf6680204c68424bc7e442ef90ac01c4df420ef5742,
        0x94823250a000d56a5d00947800dcb2f4947f5b4eb18fa1dbdc6ab16be4b71311,
        0x02d4dff98ddeac38554473964d29cdc521ee690cde5a8cd16889aa090c32c53e
    ];

    uint[1] memory e = [
        uint(0x10001)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0xff23e00f819bae424e41d6b762ea6b88801e651c831c964af31de0c1d6dda4a7,
        0xc8587d804ed12f526819da06650e7412fb627555979ed442f2663341e5fe5752,
        0x7e0ddaf453a124451674976a6a6e0a31f56a79f5b73dfac39af4f3ba4a5e8bb8,
        0x46cb5e333812756482d975ab1910162f96bfd7c58a02f113125189f5ac05291f
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 5;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 5");
  }
  function testPkcs1Sha256VerifyEm00EndPadRemoved() public {
    uint[4] memory s = [
        0x06317d3df0fa7ae350729ae2096b050dcec8909d36681ccca09a7a527b90767f,
        0x8c2318c49e09483b48df77ddb632d6ca721155165389f7795d3ede7046567864,
        0x9399242aed6d984ca74fc6c2eb4dd4bb2cd7bf2125ec853f2bf757d665b29487,
        0xbc5b63df0d0b03b18608d3d9a7576ea0954aef3d3303f7d8fd7e7f9725c114e2
    ];

    uint[1] memory e = [
        uint(0x10001)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0xb8518b80a55b365eb1850e18f88da2941c99543c2f865df3d37d114d9fc764ff,
        0xc5e2ae94f2d4ab6276bfc6bda5b6976a7dcfaa56897982880410dd5542af3ad3,
        0x4c469990cbec828327764842ef488f767c6b0c8cd1e08caec63438f2665517d1,
        0x95a4d4daf64bc2a70bd11d119eec93a060960245d162844c5f11a98cd26003e1
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 3;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 3");
  }
  function testPkcs1Sha256VerifyEmMovedLeft() public {
    uint[4] memory s = [
        0xa62e4b688bb3c4c2e11a3a0b1ef81ff4bbaa110c9b830d02bda2d364dadb2345,
        0xa8c5dca58c611515f0c09732ee6a6642d5c5c339460a9d15022f48c36e9bc2fb,
        0x8b2b0ff99005273287b8c3bed87993baf52f0e9d079281bc25a8694ed9692446,
        0x127c26c34f21e610a84f3617247ecfb3b5337fe59d1239dfb7fdac8694dbef0b
    ];

    uint[1] memory e = [
        uint(0x10001)
    ];

    uint[4] memory m = [
        0xa8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802a,
        0xafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080,
        0xede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941,
        0xada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5
    ];

    uint[4] memory data = [
        0x399b54f756514628f32ce8f1cf391d77047af55f3d43804923e5e09a188aa27f,
        0x28604f2f3cfa3d7091f3ab5c69d40d650137a597c22d531dbbdeae074f6f534a,
        0x2b297e087cd7d7125e6f8eac97f5a990859d9d3555301c5076b02f9c4d3f84d6,
        0x2b3d090c7cb1ba1841eab668c066990079f206c15d1383eb3ba58ae17bc2dc2c
    ];

    bytes memory sb = uints2bytes(s);
    bytes memory eb = uints2bytes(e);
    bytes memory mb = uints2bytes(m);
    bytes memory datab = uints2bytes(data);

    Pkcs1Sha256Verify verifier = Pkcs1Sha256Verify(DeployedAddresses.Pkcs1Sha256Verify());
    uint expected = 2;
    Assert.equal(verifier.verify(sha256(datab),sb,eb,mb), expected, "Function should return 2");
  }

  /*********************************
   * HELPER FUNCTIONS
   ********************************/
  function memcpy(uint dest, uint src, uint len) pure private {
    // Copy word-length chunks while possible
    for(; len >= 32; len -= 32) {
      assembly {
        mstore(dest, mload(src))
      }
      dest += 32;
      src += 32;
    }

    // Copy remaining bytes
    uint mask = 256 ** (32 - len) - 1;
    assembly {
      let srcpart := and(mload(src), not(mask))
      let destpart := and(mload(dest), mask)
      mstore(dest, or(destpart, srcpart))
    }
  }
  function uints2bytes(uint[4] memory v) pure returns (bytes) {
     bytes memory b = new bytes(4*32);
     uint v_ptr;
     uint b_ptr;
     assembly {
         v_ptr := v
         b_ptr := add(b,0x20)
     }
      memcpy(b_ptr,v_ptr,b.length);
      return b;
   }
   function uints2bytes(uint[1] memory v) pure returns (bytes) {
     bytes memory b = new bytes(32);
     uint v_ptr;
     uint b_ptr;
     assembly {
         v_ptr := v
         b_ptr := add(b,0x20)
     }
     memcpy(b_ptr,v_ptr,b.length);
     return b;
  }

}
