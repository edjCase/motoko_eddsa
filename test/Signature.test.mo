import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import Signature "../src/Signature";
import Text "mo:base/Text";

test(
    "Ed25519 Signature Creation and Equality",
    func() {
        // Test vector: signature bytes (64 bytes)
        let sigBytes : [Nat8] = [
            86,
            58,
            173,
            111,
            176,
            130,
            243,
            66,
            12,
            53,
            44,
            244,
            62,
            14,
            172,
            151,
            128,
            22,
            181,
            50,
            48,
            50,
            6,
            168,
            100,
            181,
            107,
            222,
            49,
            1,
            25,
            112,
            17,
            223,
            37,
            9,
            132,
            144,
            116,
            97,
            145,
            96,
            158,
            14,
            231,
            8,
            208,
            239,
            52,
            92,
            219,
            69,
            47,
            208,
            133,
            139,
            226,
            86,
            116,
            165,
            138,
            186,
            137,
            2,
        ];

        // Create a signature
        let signature = Signature.Signature(sigBytes);

        // Test equality with identical signature
        let signature2 = Signature.Signature(sigBytes);
        assert (signature.equal(signature2));

        // Test equality with different signature
        let differentBytes : [Nat8] = [
            85,
            58,
            173,
            111,
            176,
            130,
            243,
            66, // Changed first byte
            12,
            53,
            44,
            244,
            62,
            14,
            172,
            151,
            128,
            22,
            181,
            50,
            48,
            50,
            6,
            168,
            100,
            181,
            107,
            222,
            49,
            1,
            25,
            112,
            17,
            223,
            37,
            9,
            132,
            144,
            116,
            97,
            145,
            96,
            158,
            14,
            231,
            8,
            208,
            239,
            52,
            92,
            219,
            69,
            47,
            208,
            133,
            139,
            226,
            86,
            116,
            165,
            138,
            186,
            137,
            2,
        ];
        let differentSig = Signature.Signature(differentBytes);
        assert (not signature.equal(differentSig));
    },
);

test(
    "Signature to/fromBytes",
    func() {
        // Test vector: signature bytes (64 bytes)
        let sigBytes : [Nat8] = [
            86,
            58,
            173,
            111,
            176,
            130,
            243,
            66,
            12,
            53,
            44,
            244,
            62,
            14,
            172,
            151,
            128,
            22,
            181,
            50,
            48,
            50,
            6,
            168,
            100,
            181,
            107,
            222,
            49,
            1,
            25,
            112,
            17,
            223,
            37,
            9,
            132,
            144,
            116,
            97,
            145,
            96,
            158,
            14,
            231,
            8,
            208,
            239,
            52,
            92,
            219,
            69,
            47,
            208,
            133,
            139,
            226,
            86,
            116,
            165,
            138,
            186,
            137,
            2,
        ];

        // Create a signature
        let signature = Signature.Signature(sigBytes);

        // Export to raw bytes
        let rawBytes = signature.toBytes(#raw);
        assert (rawBytes == sigBytes);

        // Import from raw bytes
        let importedSig = switch (Signature.fromBytes(rawBytes.vals(), #raw)) {
            case (#ok(sig)) sig;
            case (#err(e)) Runtime.trap("Failed to import signature: " # e);
        };

        // Check equality
        assert (signature.equal(importedSig));
    },
);

test(
    "Signature to/fromText (formats)",
    func() {
        // Test vector: signature bytes (64 bytes)
        let sigBytes : [Nat8] = [
            86,
            58,
            173,
            111,
            176,
            130,
            243,
            66,
            12,
            53,
            44,
            244,
            62,
            14,
            172,
            151,
            128,
            22,
            181,
            50,
            48,
            50,
            6,
            168,
            100,
            181,
            107,
            222,
            49,
            1,
            25,
            112,
            17,
            223,
            37,
            9,
            132,
            144,
            116,
            97,
            145,
            96,
            158,
            14,
            231,
            8,
            208,
            239,
            52,
            92,
            219,
            69,
            47,
            208,
            133,
            139,
            226,
            86,
            116,
            165,
            138,
            186,
            137,
            2,
        ];

        // Create a signature
        let signature = Signature.Signature(sigBytes);

        // Define formats to test
        type FormatPair = {
            outputFormat : Signature.OutputTextFormat;
            inputFormat : Signature.InputTextFormat;
        };

        let formats : [FormatPair] = [
            {
                outputFormat = #hex({
                    byteEncoding = #raw;
                    format = { isUpper = false; prefix = #none };
                });
                inputFormat = #hex({
                    byteEncoding = #raw;
                    format = { prefix = #none };
                });
            },
            {
                outputFormat = #base64({
                    byteEncoding = #raw;
                    isUriSafe = false;
                });
                inputFormat = #base64({
                    byteEncoding = #raw;
                });
            },
            {
                outputFormat = #hex({
                    byteEncoding = #raw;
                    format = { isUpper = true; prefix = #single("0x") };
                });
                inputFormat = #hex({
                    byteEncoding = #raw;
                    format = { prefix = #single("0x") };
                });
            },
            {
                outputFormat = #base64({
                    byteEncoding = #raw;
                    isUriSafe = true;
                });
                inputFormat = #base64({
                    byteEncoding = #raw;
                });
            },
        ];

        // Test each format for roundtrip conversion
        for (format in formats.vals()) {
            let text = signature.toText(format.outputFormat);

            let importedSig = switch (Signature.fromText(text, format.inputFormat)) {
                case (#ok(sig)) sig;
                case (#err(e)) Runtime.trap("Failed to import signature from " # debug_show (format) # ": " # e);
            };

            // Check equality
            assert (signature.equal(importedSig));
        };
    },
);

test(
    "Signature Error Handling",
    func() {
        // Test with invalid signature size
        let invalidBytes : [Nat8] = [1, 2, 3]; // Too short

        let result = Signature.fromBytes(invalidBytes.vals(), #raw);
        switch (result) {
            case (#ok(_)) Runtime.trap("Should have failed with invalid signature size");
            case (#err(e)) assert (Text.startsWith(e, #text("Invalid Ed25519 signature size")));
        };

        // Test with invalid hex
        let invalidHex = "not a hex string";

        let result2 = Signature.fromText(
            invalidHex,
            #hex({
                byteEncoding = #raw;
                format = { prefix = #none };
            }),
        );

        switch (result2) {
            case (#ok(_)) Runtime.trap("Should have failed with invalid hex");
            case (#err(_)) (); // Expected error
        };

        // Test with invalid base64
        let invalidBase64 = "not a base64 string!@#";

        let result3 = Signature.fromText(
            invalidBase64,
            #base64({
                byteEncoding = #raw;
            }),
        );

        switch (result3) {
            case (#ok(_)) Runtime.trap("Should have failed with invalid base64");
            case (#err(_)) (); // Expected error
        };
    },
);
