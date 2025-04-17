import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import Debug "mo:new-base/Debug";
import Signature "../src/Signature";
import Text "mo:base/Text";

// test(
//     "a",
//     func() {
//         Debug.print("--- Testing Base Point Recovery ---");
//         let base_y : Nat = 46316835694926478169428394003475163141307993866256225615783033603165251855960;
//         let expected_bx : Nat = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
//         let isXNegative = false; // Bx is even

//         // Call the function under test
//         let recovered_bx = Signature.recoverXFromY(base_y, #ed25519, isXNegative);

//         // Compare results
//         if (recovered_bx != expected_bx) {
//             Debug.print("!!! Base point recovery FAILED !!!");
//             Debug.print("Expected Bx: " # debug_show (expected_bx));
//             Debug.print("Recovered Bx: " # debug_show (recovered_bx));
//             Runtime.trap("Base point recovery failed!");
//         } else {
//             Debug.print("Base point recovery successful!");
//         };
//         Debug.print("--- /Testing Base Point Recovery ---");
//     },
// );
// test(
//     "b",
//     func() {
//         Debug.print("--- Testing Negative Base Point Recovery ---");
//         // y is the same as the base point's y
//         let neg_base_y : Nat = 46316835694926478169428394003475163141307993866256225615783033603165251855960;
//         // Expected x is (-Bx mod p), which is odd
//         let expected_neg_bx : Nat = 42783823269122696939284341094755422415180979639778424813682678720006717057747;
//         // We expect the odd root
//         let isXNegative = true;

//         // Call the function under test
//         let recovered_neg_bx = Signature.recoverXFromY(neg_base_y, #ed25519, isXNegative);

//         // Compare results
//         if (recovered_neg_bx != expected_neg_bx) {
//             Debug.print("!!! Negative base point recovery FAILED !!!");
//             Debug.print("Expected -Bx: " # debug_show (expected_neg_bx));
//             Debug.print("Recovered x:  " # debug_show (recovered_neg_bx));
//             Runtime.trap("Negative base point recovery failed!");
//         } else {
//             Debug.print("Negative base point recovery successful!");
//         };
//         Debug.print("--- /Testing Negative Base Point Recovery ---");
//     },
// );

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
                x = 15112221349535400772501151409588531511454012693041857206046113283949847762202;
                y = 46316835694926478169428394003475163141307993866256225615783033603165251855960;
                s = 7055432450925680840815035157730575267673472388327113095507987779099519877264;
                outputByteEncoding = #raw;
                inputByteEncoding = #raw({ curve = #ed25519 });
                expected = "\60\81\d8\a1\40\0b\79\00\0e\e3\4a\53\77\ca\bd\52\35\dd\9b\a5\d8\20\3d\61\00\56\75\0e\bc\85\e3\f8\98\55\62\01\4d\f8\d5\b2\7f\17\83\0c\7a\db\fc\39\92\56\94\9e\08\74\8b\0a\2e\12\e5\34\99\72\95\05";
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
            let importedSig = switch (Signature.fromBytes(rawBytes.vals(), inputByteEncoding)) {
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
