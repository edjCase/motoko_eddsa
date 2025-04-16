import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import PublicKey "../src/PublicKey";
import Text "mo:base/Text";
import Signature "../src/Signature";

test(
  "verify public key",
  func() {
    type TestCase = {
      x : Int;
      y : Nat;
      curve : PublicKey.CurveKind;
      message : Blob;
      signature : Signature.Signature;
    };
    let testCases : [TestCase] = [{
      // Example Ed25519 key pair
      x = -15030602447897822848301521802056132637413300633176944428102945160096765538873;
      y = 25451566830020096400879881766293611881698498227504099507595969280870285874605;
      curve = #ed25519;
      // Simple test message "Hello, World!"
      message = Blob.fromArray([72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]);
      // Corresponding signature for the message
      signature = Signature.Signature(
        -2709446079449353687495251577960115125199,
        32850134408996644834936237048431127511394627251815326726394878566423705950164,
        6058151488569404433177041819706964225378086124735050383929941716708969566663,
      );
    }];

    for (testCase in testCases.vals()) {
      // Create a public key
      let publicKey = PublicKey.PublicKey(testCase.x, testCase.y, testCase.curve);

      // Verify the signature
      switch (publicKey.verify(testCase.message.vals(), testCase.signature)) {
        case (false) Runtime.trap("Signature verification failed for test case - \nX: " # debug_show testCase.x # "\nY: " # debug_show testCase.y # "\nCurve: " # debug_show testCase.curve # "\nMessage: " # debug_show testCase.message # "\nSignature:\nx-" # debug_show testCase.signature.x # "\ny-" # debug_show testCase.signature.y # "\ns-" # debug_show testCase.signature.s);
        case (true) ();
      };

    };
  },
);

test(
  "PublicKey to/fromBytes (raw)",
  func() {
    type TestCase = {
      x : Int;
      y : Nat;
      curve : PublicKey.CurveKind;
      outputByteEncoding : PublicKey.OutputByteEncoding;
      inputByteEncoding : PublicKey.InputByteEncoding;
      expected : Blob;
    };
    let testCases : [TestCase] = [
      {
        // Standard Ed25519 key
        x = 1; // Positive x (bit 7 of first byte should be 0)
        y = 25451566830020096400879881766293611881698498227504099507595969280870285874605;
        curve = #ed25519;
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ curve = #ed25519 });
        // Expected raw bytes representation (32 bytes)
        expected = "\3d\4d\57\11\69\5a\2a\24\9e\8c\77\d7\54\72\02\3a\28\be\13\f2\80\70\08\84\ef\8e\a9\75\78\58\33\35";
      },
      {
        // Ed25519 key with negative x (bit 7 of first byte should be 1)
        x = -1;
        y = 37978578207795608882999957321063445618093853134547750401238741859153462471271;
        curve = #ed25519;
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ curve = #ed25519 });
        // Expected raw bytes representation (32 bytes) with high bit set
        expected = "\d7\f0\24\40\cc\b9\de\51\44\80\17\64\9a\4a\7b\c4\42\6a\74\54\b1\aa\9e\db\fa\a5\fd\6a\0d\2f\c5\53";
      },
      {
        // Test SPKI format
        x = 0;
        y = 57331689211747138215963702027209587416104487364871635084158973919207257750058;
        curve = #ed25519;
        outputByteEncoding = #spki;
        inputByteEncoding = #spki;
        // Expected SPKI format bytes
        expected = "\30\2A\30\05\06\03\2B\65\70\03\21\00\7E\E6\95\CF\45\A8\80\D5\CD\46\05\69\58\D9\EA\FA\9C\90\B9\40\46\A3\D5\14\C9\95\0D\26\DB\7C\28\77";
      },
    ];

    for (testCase in testCases.vals()) {
      // Create a public key
      let publicKey = PublicKey.PublicKey(testCase.x, testCase.y, testCase.curve);

      // Export to raw bytes
      let rawBytes = Blob.fromArray(publicKey.toBytes(testCase.outputByteEncoding));
      if (rawBytes != testCase.expected) {
        Runtime.trap("Exported bytes do not match expected bytes " # debug_show rawBytes # " for test case:\n" # debug_show (testCase));
      };

      // Import from raw bytes
      let importedKey = switch (PublicKey.fromBytes(rawBytes.vals(), testCase.inputByteEncoding)) {
        case (#ok(key)) key;
        case (#err(e)) Runtime.trap("Failed to import key: " # e # "\nTest case:\n" # debug_show (testCase));
      };

      // Check equality
      if (not publicKey.equal(importedKey)) {
        Runtime.trap("Imported key does not match original key for test case:\n" # debug_show (testCase));
      };
    };
  },
);

test(
  "PublicKey to/fromText (formats)",
  func() {
    type TestCase = {
      x : Int;
      y : Nat;
      curve : PublicKey.CurveKind;
      outputTextFormat : PublicKey.OutputTextFormat;
      inputTextFormat : PublicKey.InputTextFormat;
      expected : Text;
    };
    let testCases : [TestCase] = [
      // Test hex encoding
      {
        x = 0;
        y = 57331689211747138215963702027209587416104487364871635084158973919207257750058;
        curve = #ed25519;
        outputTextFormat = #hex({
          byteEncoding = #raw;
          format = {
            isUpper = false;
            prefix = #none;
          };
        });
        inputTextFormat = #hex({
          byteEncoding = #raw({ curve = #ed25519 });
          format = {
            prefix = #none;
          };
        });
        expected = "7ee695cf45a880d5cd4605695859eafa9c90b94046a3d514c9950d26db7c2877";
      },
      // Test base64 encoding
      {
        x = -1;
        y = 37978578207795608882999957321063445618093853134547750401238741859153462471271;
        curve = #ed25519;
        outputTextFormat = #base64({
          byteEncoding = #raw;
          isUriSafe = false;
        });
        inputTextFormat = #base64({
          byteEncoding = #raw({ curve = #ed25519 });
        });
        expected = "1/AkQMy53lFEgBdkmkp7xEJqdFSxqp7b+qX9ag0vxVM=";
      },
      // Test PEM format
      {
        x = 1;
        y = 25451566830020096400879881766293611881698498227504099507595969280870285874605;
        curve = #ed25519;
        outputTextFormat = #pem({
          byteEncoding = #spki;
        });
        inputTextFormat = #pem({
          byteEncoding = #spki;
        });
        expected = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPU1XEWlaKiSejHfXVHICOii+E/KAcAiE746pdXhYMzU=\n-----END PUBLIC KEY-----\n";
      },
      // Test JWK format
      {
        x = 0;
        y = 57331689211747138215963702027209587416104487364871635084158973919207257750058;
        curve = #ed25519;
        outputTextFormat = #jwk;
        // JWK is only for output, not input
        inputTextFormat = #base64({
          byteEncoding = #raw({ curve = #ed25519 });
        });
        expected = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"fu6Vz0WogNXNRgVpWFnq-pyQuUBGo9UUyZUNJtt8KHc=\"}";
      },
    ];
    for (testCase in testCases.vals()) {
      let { x; y; curve; outputTextFormat; inputTextFormat; expected } = testCase;
      // Create a public key
      let publicKey = PublicKey.PublicKey(x, y, curve);

      let text = publicKey.toText(outputTextFormat);

      if (text != expected) {
        Runtime.trap("Exported text does not match expected text for test case:\nActual\n" # text # "\n" # debug_show (testCase));
      };

      let importedKey = switch (PublicKey.fromText(text, inputTextFormat)) {
        case (#ok(key)) key;
        case (#err(e)) Runtime.trap("Failed to import key from " # debug_show (inputTextFormat) # ": " # e # "\nTest case:\n" # debug_show (testCase));
      };

      // Check equality
      if (not publicKey.equal(importedKey)) {
        Runtime.trap("Imported key does not match original key for test case:\n" # debug_show (testCase));
      };
    };
  },
);
