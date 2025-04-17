import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import ASN1 "mo:asn1";
import Text "mo:new-base/Text";
import Nat32 "mo:new-base/Nat32";
import Signature "./Signature";
import BaseX "mo:base-x-encoder";
import PeekableIter "mo:itertools/PeekableIter";
import IterTools "mo:itertools/Iter";
import NACL "mo:tweetnacl";
import Sha256 "mo:sha2/Sha256";
import NatX "mo:xtended-numbers/NatX";

module {
    public type HashAlgorithm = Sha256.Algorithm;

    public type CurveKind = {
        #ed25519;
    };

    // The OID for Ed25519 (1.3.101.112)
    private let ED25519_OID : [Nat] = [1, 3, 101, 112];

    public type InputByteEncoding = {
        #raw : {
            curve : CurveKind;
        };
        #spki;
    };

    public type OutputByteEncoding = {
        #raw;
        #spki;
    };

    public type OutputTextFormat = {
        #base64 : {
            byteEncoding : OutputByteEncoding;
            isUriSafe : Bool;
        };
        #hex : {
            byteEncoding : OutputByteEncoding;
            format : BaseX.HexOutputFormat;
        };
        #pem : {
            byteEncoding : OutputByteEncoding;
        };
        #jwk;
    };

    public type InputTextFormat = {
        #base64 : {
            byteEncoding : InputByteEncoding;
        };
        #hex : {
            byteEncoding : InputByteEncoding;
            format : BaseX.HexInputFormat;
        };
        #pem : {
            byteEncoding : InputByteEncoding;
        };
    };

    public class PublicKey(x_ : Int, y_ : Nat, curve_ : CurveKind) {
        public let x = x_;
        public let y = y_;
        public let curve = curve_;

        public func equal(other : PublicKey) : Bool {
            x == other.x and y == other.y and curve == other.curve;
        };

        // Verify a message signature using this public key
        public func verify(
            msg : Iter.Iter<Nat8>,
            signature : Signature.Signature,
        ) : Bool {
            // Convert message iterator to array
            let buffer = Buffer.Buffer<Nat8>(128);
            for (byte in msg) {
                buffer.add(byte);
            };
            let msgArray = Buffer.toArray(buffer);

            // Get signature bytes
            let sigBytes = signature.toBytes(#raw);
            let bytes = toBytes(#raw);

            // Use TweetNaCl for verification
            NACL.SIGN.DETACHED.verify(msgArray, sigBytes, bytes);
        };

        // Export public key in different formats
        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#raw) {
                    switch (curve) {
                        case (#ed25519) {
                            let buffer = Buffer.Buffer<Nat8>(32);
                            NatX.encodeNat32(buffer, Nat32.fromNat(y), #msb);

                            if (x % 2 == 1) {
                                // Set the high bit if x is negative (odd)
                                buffer.put(0, buffer.get(0) | 0x80);
                            };

                            Buffer.toArray(buffer);
                        };
                    };
                };
                case (#spki) {
                    let bytes = toBytes(#raw);
                    // Create ASN.1 structure for SPKI
                    let spki : ASN1.ASN1Value = #sequence([
                        #sequence([
                            #objectIdentifier(ED25519_OID),
                        ]),
                        #bitString({
                            data = bytes;
                            unusedBits = 0;
                        }),
                    ]);

                    ASN1.encodeDER(spki);
                };
            };
        };

        public func toText(format : OutputTextFormat) : Text {
            switch (format) {
                case (#hex(hex)) {
                    let bytes = toBytes(hex.byteEncoding);
                    BaseX.toHex(bytes.vals(), hex.format);
                };
                case (#base64(base64)) {
                    let bytes = toBytes(base64.byteEncoding);
                    BaseX.toBase64(bytes.vals(), base64.isUriSafe);
                };
                case (#pem({ byteEncoding })) {
                    let bytes = toBytes(byteEncoding);
                    let keyType = switch (byteEncoding) {
                        case (#spki) ("PUBLIC");
                        case (#raw) ("ED25519 PUBLIC");
                    };
                    let base64 = BaseX.toBase64(bytes.vals(), false);

                    let iter = PeekableIter.fromIter(base64.chars());
                    var formatted = Text.fromIter(IterTools.take(iter, 64));
                    while (iter.peek() != null) {
                        formatted #= "\n" # Text.fromIter(IterTools.take(iter, 64));
                    };

                    "-----BEGIN " # keyType # " KEY-----\n" # formatted # "\n-----END " # keyType # " KEY-----\n";
                };
                case (#jwk) {
                    // JWK format for Ed25519
                    let bytes = toBytes(#raw);
                    let xb64 = BaseX.toBase64(bytes.vals(), true); // URI-safe Base64

                    // Format as JWK JSON for OKP (Octet Key Pair) with Ed25519 curve
                    "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" # xb64 # "\"}";
                };
            };
        };
    };

    public func fromBytes(bytes : Iter.Iter<Nat8>, encoding : InputByteEncoding) : Result.Result<PublicKey, Text> {
        switch (encoding) {
            case (#raw({ curve })) {
                // For Ed25519, we expect a 32-byte public key
                let keyBytes = Iter.toArray(IterTools.take(bytes, 32));

                if (keyBytes.size() != 32) {
                    return #err("Invalid Ed25519 public key: expected 32 bytes, got " # Nat.toText(keyBytes.size()));
                };

                // The bytes represent a compressed point
                // Extract if x is odd from the high bit of the first byte
                let isXOdd = (keyBytes[0] & 0x80) != 0;

                // Clear the high bit to get the pure y value
                let clearedBytes = Array.tabulate<Nat8>(
                    32,
                    func(i : Nat) : Nat8 {
                        if (i == 0) {
                            keyBytes[0] & 0x7F;
                        } else {
                            keyBytes[i];
                        };
                    },
                );

                // Convert to y coordinate
                let ?y = NatX.decodeNat(clearedBytes.vals(), #msb) else return #err("Failed to decode y coordinate from bytes");

                // For Ed25519, the x coordinate is determined from y
                // In a full implementation, we would compute x from y using curve arithmetic
                // For now, we just store if x is odd and a placeholder value
                // This is sufficient for verification using TweetNaCl
                let x : Nat = if (isXOdd) 1 else 0;

                #ok(PublicKey(x, y, curve));
            };
            case (#spki) {
                let asn1 = switch (ASN1.decodeDER(bytes)) {
                    case (#err(msg)) #err("Failed to decode SPKI data: " # msg);
                    case (#ok(asn1)) asn1;
                };

                let #sequence(seq) = asn1 else {
                    return #err("SPKI data is not a SEQUENCE");
                };

                if (seq.size() != 2) {
                    return #err("SPKI SEQUENCE should have 2 elements");
                };

                // Check algorithm identifier
                let #sequence(algoSeq) = seq[0] else {
                    return #err("Algorithm identifier is not a SEQUENCE");
                };

                if (algoSeq.size() < 1) {
                    return #err("Algorithm identifier SEQUENCE is empty");
                };

                let #objectIdentifier(algoOid) = algoSeq[0] else {
                    return #err("Algorithm identifier does not contain an OID");
                };

                let curve = if (algoOid == ED25519_OID) {
                    #ed25519;
                } else {
                    return #err("Unsupported algorithm: not Ed25519");
                };

                // Extract key data
                let #bitString(keyData) = seq[1] else {
                    return #err("Key data is not a BIT STRING");
                };

                fromBytes(keyData.data.vals(), #raw({ curve }));
            };
        };
    };

    public func fromText(value : Text, format : InputTextFormat) : Result.Result<PublicKey, Text> {
        switch (format) {
            case (#hex({ format; byteEncoding })) {
                // Convert hex to bytes
                switch (BaseX.fromHex(value, format)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid hex format: " # e);
                };
            };

            case (#base64({ byteEncoding })) {
                // Convert base64 to bytes
                switch (BaseX.fromBase64(value)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(key)) #ok(key);
                            case (#err(e)) #err("Invalid key bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid base64 format: " # e);
                };
            };

            case (#pem({ byteEncoding })) {
                let keyType = switch (byteEncoding) {
                    case (#spki) "PUBLIC";
                    case (#raw({ curve })) switch (curve) {
                        case (#ed25519) "ED25519 PUBLIC";
                    };
                };
                // Parse PEM format
                switch (extractPEMContent(value, keyType)) {
                    case (#ok(base64Content)) {
                        switch (BaseX.fromBase64(base64Content)) {
                            case (#ok(bytes)) {
                                switch (fromBytes(bytes.vals(), byteEncoding)) {
                                    case (#ok(key)) #ok(key);
                                    case (#err(e)) #err("Invalid key bytes: " # e);
                                };
                            };
                            case (#err(e)) #err("Failed to decode PEM base64: " # e);
                        };
                    };
                    case (#err(e)) #err(e);
                };
            };
        };
    };

    // Helper function to extract content from PEM format
    private func extractPEMContent(pem : Text, keyType : Text) : Result.Result<Text, Text> {
        let header = "-----BEGIN " # keyType # " KEY-----";
        let ?headerTrimmedPem = Text.stripStart(pem, #text(header)) else return #err("Invalid PEM format: missing header " # header);
        let footer = "-----END " # keyType # " KEY-----\n";
        let ?trimmedPem = Text.stripEnd(headerTrimmedPem, #text(footer)) else return #err("Invalid PEM format: missing footer " # footer);
        #ok(Text.join("", Text.split(trimmedPem, #char('\n'))));
    };
};
