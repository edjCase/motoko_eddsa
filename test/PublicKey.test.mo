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
    let testCases : [TestCase] = [];

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
    let testCases : [TestCase] = [];

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
    let testCases : [TestCase] = [];
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
