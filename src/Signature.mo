import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import BaseX "mo:base-x-encoder";
import NatX "mo:xtended-numbers/NatX";
import Int "mo:new-base/Int";
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
                    if (x < 0) {
                        // Set the sign bit for negative x
                        buffer.put(31, buffer.get(31) | 0x80);
                    };
                    // s
                    NatX.encodeNat(buffer, s, #lsb);
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
                let x : Int = if (isXNegative) -recoverXFromY(y, curve) else recoverXFromY(y, curve);
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

    private func recoverXFromY(y : Nat, curveKind : CurveKind) : Int {
        switch (curveKind) {
            case (#ed25519) {
                let ED25519_PRIME : Nat = 2 ** 255 - 19;
                let ED25519_D_NUM : Int = -121665;
                let ED25519_D_DEN : Nat = 121666;

                // Compute y²
                let y_squared = (y * y) % ED25519_PRIME;

                // Compute numerator: (y² - 1) % p
                let num : Nat = if (y_squared > 1) {
                    y_squared - 1;
                } else {
                    // Handle underflow in modular arithmetic
                    ED25519_PRIME - (1 - y_squared);
                };

                // Compute d*y² in the field
                // For Ed25519, we need to compute -121665/121666 * y²
                // This requires modular arithmetic with fractions

                // First compute d_num * y² (the negative value)
                let d_num_y_squared = (Int.abs(ED25519_D_NUM) * y_squared) % ED25519_PRIME;

                // Compute modular inverse of d_den
                let d_den_inv = modInverse(ED25519_D_DEN, ED25519_PRIME);

                // d*y² = (d_num * y² * d_den_inv) % p
                let d_y_squared = (d_num_y_squared * d_den_inv) % ED25519_PRIME;

                // For negative d, we need to negate in the field
                let d_y_squared_signed : Int = ED25519_PRIME - d_y_squared;

                // Compute denominator: (d*y² - 1) % p
                let den : Nat = if (d_y_squared_signed > 1) {
                    Int.abs(d_y_squared_signed - 1);
                } else {
                    ED25519_PRIME - Int.abs(1 - d_y_squared_signed);
                };

                // Compute den_inv = 1/den in the field
                let den_inv = modInverse(den, ED25519_PRIME);

                // Compute (num * den_inv) % p
                let x_squared = (num * den_inv) % ED25519_PRIME;

                // Now we need to compute the square root in the field
                sqrtModP(x_squared, ED25519_PRIME);
            };
        };
    };

    private func modInverse(a : Nat, m : Nat) : Nat {
        // Extended Euclidean Algorithm to find modular inverse
        var t : Int = 0;
        var newT : Int = 1;
        var r : Nat = m;
        var newR : Nat = a;
        var quotient : Nat = 0;
        var temp : Int = 0;

        while (newR != 0) {
            quotient := r / newR;

            temp := newT;
            newT := t - Int.fromNat(quotient) * newT;
            t := temp;

            temp := Int.fromNat(newR);
            newR := r - quotient * newR;
            r := Int.abs(temp);
        };

        if (r > 1) {
            // a is not invertible
            return 0; // Error case
        };

        if (t < 0) {
            t := t + Int.fromNat(m);
        };

        return Int.abs(t);
    };
    private func sqrtModP(n : Nat, p : Nat) : Nat {
        // Edge cases
        if (n == 0) return 0;
        if (p == 2) return n % 2;

        // Check that n is a quadratic residue using Euler's criterion
        if (modPow(n, (p - 1) / 2, p) != 1) {
            // Not a quadratic residue
            return 0;
        };

        // For primes p ≡ 3 (mod 4), we can use the formula: sqrt(n) = n^((p+1)/4) mod p
        if (p % 4 == 3) {
            let exp = (p + 1) / 4;
            return modPow(n, exp, p);
        };

        // Otherwise, use Tonelli-Shanks algorithm for p ≡ 1 (mod 4)

        // Factor p-1 as q * 2^s where q is odd
        var q : Nat = p - 1;
        var s = 0;
        while (q % 2 == 0) {
            q := q / 2;
            s += 1;
        };

        // Find a quadratic non-residue z
        var z = 2;
        while (modPow(z, (p - 1) / 2, p) != (p - 1 : Nat)) {
            z += 1;
        };

        // Initialize algorithm variables
        var m = s;
        var c = modPow(z, q, p);
        var t = modPow(n, q, p);
        var r = modPow(n, (q + 1) / 2, p);

        // Main loop
        while (t != 1) {
            // Find the least i, 0 < i < m, such that t^(2^i) ≡ 1 (mod p)
            var i = 1;
            var squared = (t * t) % p;
            while (i < m and squared != 1) {
                squared := (squared * squared) % p;
                i += 1;
            };

            if (i == m) {
                // No solution exists
                return 0;
            };

            // Calculate b = c^(2^(m-i-1)) mod p
            let exp = Nat.pow(2, Int.abs(m - i - 1));
            let b = modPow(c, exp, p);

            // Update variables for next iteration
            m := i;
            c := (b * b) % p;
            t := (t * b * b) % p;
            r := (r * b) % p;
        };

        return r;
    };

    private func modPow(base : Nat, exp : Nat, modulus : Nat) : Nat {
        var result = 1;
        var b = base % modulus;
        var e = exp;

        while (e > 0) {
            if (e % 2 == 1) {
                result := (result * b) % modulus;
            };
            e := e / 2;
            b := (b * b) % modulus;
        };

        result;
    };
};
