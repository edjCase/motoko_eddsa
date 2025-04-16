import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import Signature "../src/Signature";
import Text "mo:base/Text";

test(
    "Signature to/fromBytes",
    func() {
        type TestCase = {
            x : Int;
            y : Nat;
            s : Nat;
            outputByteEncoding : Signature.OutputByteEncoding;
            inputByteEncoding : Signature.InputByteEncoding;
            expected : Blob;
        };
        let testCases : [TestCase] = [];
        for (testCase in testCases.vals()) {
            let { x; y; s; outputByteEncoding; inputByteEncoding; expected } = testCase;
            // Create a signature
            let signature = Signature.Signature(x, y, s);

            // Export to raw bytes
            let rawBytes = Blob.fromArray(signature.toBytes(outputByteEncoding));
            if (rawBytes != expected) {
                Runtime.trap("Exported bytes do not match expected bytes");
            };

            // Import from raw bytes
            let importedSig = switch (Signature.fromBytes(rawBytes.vals(), inputByteEncoding)) {
                case (#ok(sig)) sig;
                case (#err(e)) Runtime.trap("Failed to import signature: " # e);
            };

            // Check equality
            if (not signature.equal(importedSig)) {
                Runtime.trap("Imported signature does not match original");
            };
        };
    },
);

test(
    "Signature to/fromText (formats)",
    func() {
        type TestCase = {
            x : Int;
            y : Nat;
            s : Nat;
            inputFormat : Signature.InputTextFormat;
            outputFormat : Signature.OutputTextFormat;
            expected : Text;
        };
        let testCases : [TestCase] = [];

        for (testCase in testCases.vals()) {
            let { x; y; s; inputFormat; outputFormat; expected } = testCase;
            // Create a signature
            let signature = Signature.Signature(x, y, s);

            let text = signature.toText(outputFormat);
            if (text != expected) {
                Runtime.trap("Exported text does not match expected text for test case:\nActual\n" # text # "\nExpected\n" # expected # "\nTest case:\n" # debug_show (testCase));
            };

            let importedSig = switch (Signature.fromText(text, inputFormat)) {
                case (#ok(sig)) sig;
                case (#err(e)) Runtime.trap("Failed to import signature from " # debug_show (inputFormat) # ": " # e);
            };

            // Check equality
            if (not signature.equal(importedSig)) {
                Runtime.trap("Imported signature does not match original signature for test case:\n" # debug_show (testCase));
            };
        };
    },
);
