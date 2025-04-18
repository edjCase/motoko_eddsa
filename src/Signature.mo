import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import BaseX "mo:base-x-encoder";
import NatX "mo:xtended-numbers/NatX";
import Int "mo:new-base/Int";
import IterTools "mo:itertools/Iter";
import Common "Common";

module {
    public type OutputByteEncoding = {
        #raw;
    };

    public type InputByteEncoding = {
        #raw : {
            curve : CurveKind;
        };
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

        // Convert signature to bytes array (raw format)
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
                    BaseX.toBase64(bytes.vals(), base64.isUriSafe);
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
