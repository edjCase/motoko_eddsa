import PublicKeyModule "./PublicKey";
import SignatureModule "./Signature";
import Iter "mo:base/Iter";
import Result "mo:base/Result";

module {
    public type PublicKey = PublicKeyModule.PublicKey;
    public type Signature = SignatureModule.Signature;

    // Create a public key from raw bytes
    public func PublicKey(
        x : Int,
        y : Nat,
        curveKind : PublicKeyModule.CurveKind,
    ) : PublicKey = PublicKeyModule.PublicKey(x, y, curveKind);

    // Import public key from bytes
    public func publicKeyFromBytes(
        bytes : Iter.Iter<Nat8>,
        encoding : PublicKeyModule.InputByteEncoding,
    ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromBytes(bytes, encoding);

    // Import public key from text
    public func publicKeyFromText(
        text : Text,
        encoding : PublicKeyModule.InputTextFormat,
    ) : Result.Result<PublicKey, Text> = PublicKeyModule.fromText(text, encoding);

    // Create a signature from raw bytes
    public func Signature(
        x : Int,
        y : Nat,
        s : Nat,
    ) : Signature = SignatureModule.Signature(x, y, s);

    // Import signature from bytes
    public func signatureFromBytes(
        bytes : Iter.Iter<Nat8>,
        encoding : SignatureModule.InputByteEncoding,
    ) : Result.Result<Signature, Text> = SignatureModule.fromBytes(bytes, encoding);

    // Import signature from text
    public func signatureFromText(
        text : Text,
        encoding : SignatureModule.InputTextFormat,
    ) : Result.Result<Signature, Text> = SignatureModule.fromText(text, encoding);
};
