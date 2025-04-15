import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import BaseX "mo:base-x-encoder";

module {
    public type OutputByteEncoding = {
        #raw;
    };

    public type InputByteEncoding = {
        #raw;
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

    public class Signature(
        signatureBytes_ : [Nat8]
    ) {
        public let bytes = signatureBytes_;

        public func equal(other : Signature) : Bool {
            if (bytes.size() != other.bytes.size()) {
                return false;
            };

            for (i in bytes.keys()) {
                if (bytes[i] != other.bytes[i]) {
                    return false;
                };
            };
            return true;
        };

        public func getBytes() : [Nat8] {
            bytes;
        };

        // Convert signature to bytes array (raw format)
        public func toBytes(encoding : OutputByteEncoding) : [Nat8] {
            switch (encoding) {
                case (#raw) bytes;
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
            case (#raw) {
                let buffer = Buffer.Buffer<Nat8>(64);
                var count = 0;
                for (byte in bytes) {
                    buffer.add(byte);
                    count += 1;
                };

                if (count != 64) {
                    return #err("Invalid Ed25519 signature size: expected 64 bytes, got " # Nat.toText(count));
                };

                #ok(Signature(Buffer.toArray(buffer)));
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
