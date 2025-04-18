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
        let testCases : [TestCase] = [
            {
                x = 32659244743902125671750775541108600435972519608980791545566174304356588384442;
                y = 37812647512915033038667227002500228956020200491405235946433044056539611995827;
                s = 7055432450925680840815035157730575267673472388327113095507987779099519877264;
                outputByteEncoding = #raw;
                inputByteEncoding = #raw({ curve = #ed25519 });
                expected = "\b3\1e\ff\d7\15\22\fb\03\e1\f9\32\d5\f4\e2\11\5b\43\f5\ae\9d\79\34\07\c7\52\a3\6b\49\37\33\99\53\90\00\dc\10\cf\0e\e2\69\5c\14\3d\f1\ce\79\76\10\2f\50\c8\d9\99\e3\65\52\2e\9b\65\6d\b6\3b\99\0f";
            },
        ];
        for (testCase in testCases.vals()) {
            let { x; y; s; outputByteEncoding; inputByteEncoding; expected } = testCase;
            // Create a signature
            let signature = Signature.Signature(x, y, s);

            // Export to raw bytes
            let rawBytes = Blob.fromArray(signature.toBytes(outputByteEncoding));
            if (rawBytes != expected) {
                Runtime.trap("Exported bytes do not match expected bytes\nExpected\n" # debug_show expected # "\nActual\n" # debug_show rawBytes);
            };

            // Import from raw bytes
            let importedSig = switch (Signature.fromBytes(expected.vals(), inputByteEncoding)) {
                case (#ok(sig)) sig;
                case (#err(e)) Runtime.trap("Failed to import signature: " # e);
            };

            // Check equality
            if (not signature.equal(importedSig)) {
                Runtime.trap("Imported signature does not match original\nOriginal\n" # debug_show { x = signature.x; y = signature.y; s = signature.s } # "\nImported\n" # debug_show { x = importedSig.x; y = importedSig.y; s = importedSig.s });
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
        let testCases : [TestCase] = [
            // Test hex encoding
            {
                x = 32659244743902125671750775541108600435972519608980791545566174304356588384442;
                y = 37812647512915033038667227002500228956020200491405235946433044056539611995827;
                s = 7055432450925680840815035157730575267673472388327113095507987779099519877264;
                inputFormat = #hex({
                    byteEncoding = #raw({ curve = #ed25519 });
                    format = {
                        prefix = #none;
                    };
                });
                outputFormat = #hex({
                    byteEncoding = #raw;
                    format = {
                        isUpper = false;
                        prefix = #none;
                    };
                });
                expected = "b31effd71522fb03e1f932d5f4e2115b43f5ae9d793407c752a36b49373399539000dc10cf0ee2695c143df1ce7976102f50c8d999e365522e9b656db63b990f";
            },
        ];

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
