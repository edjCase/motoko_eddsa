import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import BaseX "mo:base-x-encoder";
import NatX "mo:xtended-numbers/NatX";
import Int "mo:new-base/Int";
import Debug "mo:new-base/Debug";
import Runtime "mo:new-base/Runtime";
import Blob "mo:new-base/Blob";
import IterTools "mo:itertools/Iter";

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
    public type CurveKind = {
        #ed25519;
    };

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
                    Debug.print("Buffer after y: " # debug_show (Blob.fromArray(Buffer.toArray(buffer))));
                    while (buffer.size() < 32) {
                        buffer.add(0); // Pad with zeros
                    };
                    Debug.print("Buffer after y and padding: " # debug_show (Blob.fromArray(Buffer.toArray(buffer))));
                    let final_byte_31 : Nat8 = if (x % 2 == 1) {
                        // Odd x: SET the MSB
                        buffer.get(31) | 0x80;
                    } else {
                        // Even x: CLEAR the MSB
                        buffer.get(31) & 0x7F;
                    };
                    buffer.put(31, final_byte_31);
                    Debug.print("Buffer after x MSB: " # debug_show (Blob.fromArray(Buffer.toArray(buffer))));
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
                let x : Int = recoverXFromY(y, curve, isXNegative);
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
    public func recoverXFromY(y : Nat, curveKind : CurveKind, isXNegative : Bool) : Nat {

        switch (curveKind) {
            case (#ed25519) {
                // Ed25519 constants
                // p = 2^255 - 19
                let p : Nat = Nat.pow(2, 255) - 19;

                // d = -121665 / 121666 mod p
                // d = -121665 * modInv(121666, p) mod p
                let d_num : Nat = 121665;
                let d_den : Nat = 121666;

                // Calculate modular inverse of d_den using our implemented utility
                let d_den_inv = NatUtils.modInv(d_den, p);

                // Calculate d = (-d_num * d_den_inv) mod p
                var d_term1 : Nat = p - d_num;
                // Add debug prints for operands of d calculation
                var d : Nat = Nat.mul(d_term1, d_den_inv) % p;

                // Calculate y^2 mod p
                let y_squared = NatUtils.modPow(y, 2, p);

                // Calculate Numerator: (y^2 - 1) mod p
                let numerator = (y_squared + p - 1) % p;

                // Calculate Denominator: (1 + d * y^2) mod p
                let dy_squared = Nat.mul(d, y_squared) % p;
                let denominator = (1 + dy_squared) % p;

                // Check if denominator is zero
                if (Nat.equal(denominator, 0)) {
                    Runtime.trap("Denominator is zero in Ed25519 point recovery.");
                };

                // Calculate modular inverse of the denominator
                let denominator_inv = NatUtils.modInv(denominator, p);

                // Add debug prints for operands of x_squared calculation
                // Calculate x^2 = numerator * denominator_inv mod p
                let x_squared = Nat.mul(numerator, denominator_inv) % p;

                // Calculate the modular square root of x_squared mod p
                let exponent = (p + 3) / 8;
                let x_root1 = NatUtils.modPow(x_squared, exponent, p);

                // Verify the root: (x_root1^2) % p == x_squared
                let x_root1_squared = NatUtils.modPow(x_root1, 2, p);
                if (x_root1_squared != x_squared) {
                    Runtime.trap("Invalid y-coordinate or calculation error: cannot find square root for x^2.");
                };

                // The two possible roots are x_root1 and (p - x_root1) mod p
                let x_root2 = (p - x_root1) % p;

                // Determine the correct root based on the sign (LSB)
                let is_root1_negative : Bool = (x_root1 % 2 == 1);

                // Return the root that matches the requested sign
                let final_x : Nat = if (isXNegative == is_root1_negative) {
                    x_root1;
                } else {
                    assert ((x_root2 % 2 == 1) != is_root1_negative); // Check parity consistency (fixed #assert)
                    x_root2;
                };
                return final_x;
            };
            // Handle other curve kinds if they were defined
            // case (...) { ... }
        };
        // Should be unreachable if curveKind is restricted to #ed25519
        Runtime.trap("Unsupported curve kind for recoverXFromY");
    };

    // ==================================================
    // Nat utility functions for modular arithmetic
    // ==================================================
    module NatUtils {

        /**
     * Calculates (base ^ exponent) mod modulus efficiently.
     */
        public func modPow(base : Nat, exponent : Nat, modulus : Nat) : Nat {
            // Debug.print("modPow(base=" # debug_show(base) # ", exp=" # debug_show(exponent) # ", mod=" # debug_show(modulus) # ")"); // Optional: uncomment if needed
            if (Nat.equal(modulus, 0)) {
                Runtime.trap("modPow: Modulus cannot be zero");
            };
            if (Nat.equal(modulus, 1)) { return 0 };
            if (Nat.equal(exponent, 0)) { return 1 };

            var res : Nat = 1;
            var b : Nat = base % modulus;
            var exp : Nat = exponent;

            while (exp > 0) {
                if (exp % 2 == 1) {
                    res := (res * b) % modulus;
                };
                b := (b * b) % modulus;
                exp := exp / 2;
            };
            // Debug.print("modPow result: " # debug_show(res)); // Optional: uncomment if needed
            return res;
        };

        /**
     * Calculates the modular multiplicative inverse of a modulo m.
     * Includes debug prints.
     */
        public func modInv(a : Nat, m : Nat) : Nat {
            if (m <= 1) { Runtime.trap("modInv: Modulus must be > 1") };

            let a_reduced : Nat = a % m;
            if (Nat.equal(a_reduced, 0)) {
                // Inverse of 0 doesn't exist unless modulus is 1 (which is disallowed)
                Runtime.trap("modInv: Inverse does not exist (a is congruent to 0 mod m)");
            };

            // Use implicit Nat <: Int subtyping for conversion
            let a_int : Int = a_reduced;
            let m_int : Int = m;

            // Call the helper function that works with Ints
            let (gcd, x, y) = _extendedEuclideanAlgorithm(a_int, m_int);

            // Check if inverse exists. Since b (m_int) is positive, gcd returned by
            // the new base case (b, 0, 1) will be positive.
            // We need gcd to be 1 for the inverse to exist.
            if (gcd != 1) {
                Runtime.trap("modInv: Inverse does not exist (a and m are not coprime, gcd=" # debug_show (gcd) # ")");
            };

            // The inverse is x. We need to map it to the range [0, m-1].
            let result_int : Int = (x % m_int + m_int) % m_int;

            assert (result_int >= 0);
            return Int.abs(result_int); // Convert back to Nat
        };

        /**
     * Extended Euclidean Algorithm helper function.
     * Uses alternative base case.
     */
        private func _extendedEuclideanAlgorithm(a : Int, b : Int) : (Int, Int, Int) {
            // Debug.print("_extendedEuclideanAlgorithm(a=" # debug_show(a) # ", b=" # debug_show(b) # ")"); // Optional: uncomment for deep trace

            // MODIFIED: Use alternative standard base case: gcd(0, b) = b, x = 0, y = 1
            if (a == 0) {
                // Since b (modulus m) is positive in modInv, gcd returned (b) will be positive.
                return (b, 0, 1);
            };

            // Recursive step (standard algorithm)
            let q : Int = b / a;
            let r : Int = b % a; // Motoko's remainder

            let (gcd, x1, y1) = _extendedEuclideanAlgorithm(r, a);

            // Calculate x and y using results from recursive call
            let x = y1 - q * x1;
            let y = x1;

            return (gcd, x, y);
        };
    };
};
