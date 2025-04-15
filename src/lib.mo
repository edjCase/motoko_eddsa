import PublicKeyModule "./PublicKey";
import SignatureModule "./Signature";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Principal "mo:base/Principal";

module {
    public type PublicKey = PublicKeyModule.PublicKey;
    public type Signature = SignatureModule.Signature;

    // Create a public key from raw bytes
    public func PublicKey(
        bytes : [Nat8]
    ) : PublicKey = PublicKeyModule.PublicKey(bytes);

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

    // Convert a public key to a Principal
    public func publicKeyToPrincipal(
        publicKey : PublicKey
    ) : Principal = publicKey.toPrincipal();

    // Create a signature from raw bytes
    public func Signature(
        bytes : [Nat8]
    ) : Signature = SignatureModule.Signature(bytes);

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
