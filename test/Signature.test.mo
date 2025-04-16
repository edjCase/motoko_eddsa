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
                // Standard Ed25519 signature
                x = -2709446079449353687495251577960115125199;
                y = 32850134408996644834936237048431127511394627251815326726394878566423705950164;
                s = 6058151488569404433177041819706964225378086124735050383929941716708969566663;
                outputByteEncoding = #raw;
                inputByteEncoding = #raw({ curve = #ed25519 });
                // Expected raw bytes representation (64 bytes)
                expected = "\84\4c\7a\f3\45\8f\33\6a\43\5a\54\3a\85\0d\36\08\19\a1\92\d1\fc\de\3f\3d\c3\76\59\7b\3f\c4\8a\80\27\b5\7c\a3\19\98\66\45\dc\7a\0e\ab\d0\f9\d5\36\c1\e6\37\73\03\f3\c0\7e\1f\fc\d2\18\da\a1\c4\0d";
            },
            {
                // Ed25519 signature with negative x (bit 7 of first byte should be 1)
                x = -5471598209892512054862324589241706472214;
                y = 45238649199836881920793566056889134909737591514882012296902797922742564273782;
                s = 24209461726586500677365695679121562740559686926116165967384438823388206760992;
                outputByteEncoding = #raw;
                inputByteEncoding = #raw({ curve = #ed25519 });
                // Expected raw bytes representation (64 bytes) with high bit set in R
                expected = "\96\a2\c6\5e\31\7f\8b\90\12\4c\d3\e4\47\4f\31\1a\53\24\73\89\5d\bd\c3\21\0c\7b\73\19\f0\c4\8e\86\e0\91\34\a2\c7\33\ed\49\b2\f0\5e\10\3f\56\79\22\60\bf\d4\a3\84\64\97\9c\f5\6a\54\ab\d9\96\29\35";
            },
        ];
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
        let testCases : [TestCase] = [
            // Test hex encoding
            {
                x = -2709446079449353687495251577960115125199;
                y = 32850134408996644834936237048431127511394627251815326726394878566423705950164;
                s = 6058151488569404433177041819706964225378086124735050383929941716708969566663;
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
                expected = "844c7af3458f336a435a543a850d360819a192d1fcde3f3dc376597b3fc48a8027b57ca319986645dc7a0eabd0f9d536c1e6377303f3c07e1ffcd218daa1c40d";
            },
            // Test base64 encoding
            {
                x = -5471598209892512054862324589241706472214;
                y = 45238649199836881920793566056889134909737591514882012296902797922742564273782;
                s = 24209461726586500677365695679121562740559686926116165967384438823388206760992;
                inputFormat = #base64({
                    byteEncoding = #raw({ curve = #ed25519 });
                });
                outputFormat = #base64({
                    byteEncoding = #raw;
                    isUriSafe = false;
                });
                expected = "lqLGXjF/i5ASLNPkR08xGlMkc4ldvcMhDHtzGfDEjobokySSxxPtSbLwXhA/VnkiYL/Uo4Rkl5z1alSr2ZYpNQ==";
            },
            // Test URI-safe base64 encoding
            {
                x = -2709446079449353687495251577960115125199;
                y = 32850134408996644834936237048431127511394627251815326726394878566423705950164;
                s = 6058151488569404433177041819706964225378086124735050383929941716708969566663;
                inputFormat = #base64({
                    byteEncoding = #raw({ curve = #ed25519 });
                });
                outputFormat = #base64({
                    byteEncoding = #raw;
                    isUriSafe = true;
                });
                expected = "hEx68UWPMzpDWlQ6hQ02CBmhktH83j89w3ZZez_EioAnbXyjGZhmRdx6DqvQ-dU2weY3cwPzwH4f_NIY2qHEDQ==";
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
