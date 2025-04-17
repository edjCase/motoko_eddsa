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
      x = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
      y = 46316835694926478169428394003475163141307993866256225615783033603165251855960;
      curve = #ed25519;
      // Simple test message "Hello"
      message = "\48\65\6c\6c\6f";
      // Corresponding signature for the message
      signature = Signature.Signature(
        15112221349535400772501151409588531511454012693041857206046113283949847762202,
        46316835694926478169428394003475163141307993866256225615783033603165251855960,
        7055432450925680840815035157730575267673472388327113095507987779099519877264,
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
        x = 0; // Positive x (bit 7 of first byte should be 0)
        y = 0;
        curve = #ed25519;
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ curve = #ed25519 });
        // Expected raw bytes representation (32 bytes)
        expected = "\e9\f2\dc\b6\bb\fb\9f\bd\41\d9\84\49\02\65\cb\62\49\18\c3\b0\eb\16\b1\b3\0c\fe\ea\65\6a\24\33\60";
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
        y = 0;
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
        expected = "e9f2dcb6bbfb9fbd41d984490265cb624918c3b0eb16b1b30cfeea656a243360";
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
