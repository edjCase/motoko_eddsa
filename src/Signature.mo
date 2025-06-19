import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import BaseX "mo:base-x-encoder";
import NatX "mo:xtended-numbers/NatX";
import Int "mo:new-base/Int";
import IterTools "mo:itertools/Iter";
import Text "mo:new-base/Text";
import Runtime "mo:new-base/Runtime";
import Common "Common";
import ASN1 "mo:asn1";

module {
    public type OutputByteEncoding = {
        #raw;
        #der;
    };

    public type InputByteEncoding = {
        #raw : {
            curve : CurveKind;
        };
        #der : {
            curve : CurveKind;
        };
    };

    public type OutputTextFormat = {
        #base64 : {
            byteEncoding : OutputByteEncoding;
            format : BaseX.Base64OutputFormat;
        };
        #hex : {
            byteEncoding : OutputByteEncoding;
            format : BaseX.HexOutputFormat;
        };
    };

    public type InputTextFormat = {
        #base64 : {
            byteEncoding : InputByteEncoding;
        };
        #hex : {
            byteEncoding : InputByteEncoding;
            format : BaseX.HexInputFormat;
        };
    };
    public type CurveKind = Common.CurveKind;

    public type Point = {
        x : Int;
        y : Nat;
    };

    public class Signature(
        x_ : Int,
        y_ : Nat,
        s_ : Nat,
    ) {
        public let x = x_;
        public let y = y_;
        public let s = s_;

        public func equal(other : Signature) : Bool {
            x == other.x and y == other.y and s == other.s;
        };

        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#raw) {
                    let buffer = Buffer.Buffer<Nat8>(64);
                    // y
                    NatX.encodeNat(buffer, y, #lsb);
                    while (buffer.size() < 32) {
                        buffer.add(0); // Pad with zeros
                    };
                    let final_byte_31 : Nat8 = if (x % 2 == 1) {
                        // Odd x: SET the MSB
                        buffer.get(31) | 0x80;
                    } else {
                        // Even x: CLEAR the MSB
                        buffer.get(31) & 0x7F;
                    };
                    buffer.put(31, final_byte_31);
                    // s
                    NatX.encodeNat(buffer, s, #lsb);
                    while (buffer.size() < 64) {
                        buffer.add(0); // Pad with zeros
                    };
                    Buffer.toArray(buffer);
                };
                case (#der) {
                    let buffer = Buffer.Buffer<Nat8>(64);
                    // y
                    NatX.encodeNat(buffer, y, #lsb);
                    while (buffer.size() < 32) {
                        buffer.add(0); // Pad with zeros
                    };
                    let final_byte_31 : Nat8 = if (x % 2 == 1) {
                        // Odd x: SET the MSB
                        buffer.get(31) | 0x80;
                    } else {
                        // Even x: CLEAR the MSB
                        buffer.get(31) & 0x7F;
                    };
                    buffer.put(31, final_byte_31);
                    let ?r = NatX.decodeNat(buffer.vals(), #lsb) else Runtime.trap("Failed to decode r");

                    // Create the ASN.1 DER structure
                    // SEQUENCE { INTEGER r, INTEGER s }
                    let asn1Value : ASN1.ASN1Value = #sequence([
                        #integer(r),
                        #integer(s),
                    ]);

                    // Encode to DER format
                    ASN1.encodeDER(asn1Value);
                };
            };
        };

        // Convert signature to text representation
        public func toText(format : OutputTextFormat) : Text {
            switch (format) {
                case (#hex(hex)) {
                    let bytes = toBytes(hex.byteEncoding);
                    BaseX.toHex(bytes.vals(), hex.format);
                };
                case (#base64(base64)) {
                    let bytes = toBytes(base64.byteEncoding);
                    BaseX.toBase64(bytes.vals(), base64.format);
                };
            };
        };
    };

    public func fromBytes(
        bytes : Iter.Iter<Nat8>,
        encoding : InputByteEncoding,
    ) : Result.Result<Signature, Text> {
        switch (encoding) {
            case (#raw({ curve })) {
                let rBytes = bytes |> IterTools.take(_, 32) |> Buffer.fromIter<Nat8>(_);
                let isXNegative = rBytes.get(31) & 0x80 == 0x80;
                if (isXNegative) {
                    // Clear the sign bit for negative x
                    rBytes.put(31, rBytes.get(31) & 0x7F);
                };
                let ?y = NatX.decodeNat(rBytes.vals(), #lsb) else return #err("Invalid signature bytes, unable to decode R");
                let x : Int = Common.recoverXFromY(y, curve, isXNegative);
                let ?s = NatX.decodeNat(bytes, #lsb) else return #err("Invalid signature bytes, unable to decode s");

                #ok(Signature(x, y, s));
            };
            case (#der({ curve })) {
                // Try to decode the DER bytes as ASN.1
                let asn1Result = ASN1.decodeDER(bytes);
                switch (asn1Result) {
                    case (#err(e)) {
                        return #err("Failed to decode DER: " # e);
                    };
                    case (#ok(asn1)) {
                        // Check if it's a SEQUENCE
                        let #sequence(seq) = asn1 else {
                            return #err("Expected ASN.1 SEQUENCE, got something else");
                        };

                        // Check if it has exactly 2 elements (r and s)
                        if (seq.size() != 2) {
                            return #err("Expected SEQUENCE with 2 elements, got " # Nat.toText(seq.size()));
                        };

                        // Check if both elements are INTEGERs
                        let #integer(rInt) = seq[0] else {
                            return #err("Expected INTEGER for R component");
                        };

                        let #integer(sInt) = seq[1] else {
                            return #err("Expected INTEGER for S component");
                        };

                        // Convert back to integer values
                        // Convert R to little-endian bytes for our internal representation
                        let rBuffer = Buffer.Buffer<Nat8>(32);
                        NatX.encodeNat(rBuffer, Int.abs(rInt), #lsb);
                        while (rBuffer.size() < 32) {
                            rBuffer.add(0);
                        };

                        // Extract the sign bit and recover x
                        let isXNegative = rInt < 0;
                        let final_byte_31 : Nat8 = if (isXNegative) {
                            rBuffer.get(31) | 0x80;
                        } else {
                            rBuffer.get(31) & 0x7F;
                        };
                        rBuffer.put(31, final_byte_31);

                        let ?y = NatX.decodeNat(rBuffer.vals(), #lsb) else {
                            return #err("Invalid R component");
                        };

                        let x : Int = Common.recoverXFromY(y, curve, isXNegative);

                        // Get the S value directly
                        let s = Int.abs(sInt);

                        #ok(Signature(x, y, s));
                    };
                };
            };
        };
    };

    public func fromText(
        value : Text,
        encoding : InputTextFormat,
    ) : Result.Result<Signature, Text> {
        switch (encoding) {
            case (#hex({ format; byteEncoding })) {
                // Convert hex to bytes
                switch (BaseX.fromHex(value, format)) {
                    case (#ok(bytes)) {
                        switch (fromBytes(bytes.vals(), byteEncoding)) {
                            case (#ok(signature)) #ok(signature);
                            case (#err(e)) #err("Invalid signature bytes: " # e);
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
                            case (#ok(signature)) #ok(signature);
                            case (#err(e)) #err("Invalid signature bytes: " # e);
                        };
                    };
                    case (#err(e)) #err("Invalid base64 format: " # e);
                };
            };
        };
    };
};
