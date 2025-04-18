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
      x : Nat;
      y : Nat;
      curve : PublicKey.CurveKind;
      message : Blob;
      signature : Signature.Signature;
    };
    let testCases : [TestCase] = [{
      x = 51286398080436808364751719791652616808950448576822237245355328773964350987914;
      y = 43512393995653313780034091491436412746798652980930200433568831129039272735465;
      curve = #ed25519;
      // Simple test message "Hello"
      message = "\48\65\6c\6c\6f";
      signature = Signature.Signature(
        32659244743902125671750775541108600435972519608980791545566174304356588384442,
        37812647512915033038667227002500228956020200491405235946433044056539611995827,
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
      x : Nat;
      y : Nat;
      curve : PublicKey.CurveKind;
      outputByteEncoding : PublicKey.OutputByteEncoding;
      inputByteEncoding : PublicKey.InputByteEncoding;
      expected : Blob;
    };
    let testCases : [TestCase] = [
      {
        x = 51286398080436808364751719791652616808950448576822237245355328773964350987914;
        y = 43512393995653313780034091491436412746798652980930200433568831129039272735465;
        curve = #ed25519;
        outputByteEncoding = #raw;
        inputByteEncoding = #raw({ curve = #ed25519 });
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
        Runtime.trap("Imported key does not match original key for test case:\nTestCase\n" # debug_show (testCase) # "\nOriginal\n" # debug_show { x = publicKey.x; y = publicKey.y } # "\nImported\n" # debug_show { x = importedKey.x; y = importedKey.y });
      };
    };
  },
);

test(
  "PublicKey to/fromText (formats)",
  func() {
    type TestCase = {
      x : Nat;
      y : Nat;
      curve : PublicKey.CurveKind;
      outputTextFormat : PublicKey.OutputTextFormat;
      inputTextFormat : PublicKey.InputTextFormat;
      expected : Text;
    };
    let testCases : [TestCase] = [
      // Test hex encoding
      {
        x = 51286398080436808364751719791652616808950448576822237245355328773964350987914;
        y = 43512393995653313780034091491436412746798652980930200433568831129039272735465;
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
