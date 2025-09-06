import Bench "mo:bench";
import Nat "mo:core@1/Nat";
import Result "mo:core@1/Result";
import Blob "mo:core@1/Blob";
import Runtime "mo:core@1/Runtime";
import EdDSA "../src";

module {

  public func init() : Bench.Bench {
    // Test data for benchmarking
    let messageData : Blob = "hello";

    // Real Ed25519 test key pair and signature generated using OpenSSL
    // Private key (for reference only, not used in benchmarks):
    // Hex: c85d6880905f5b7cce172f4c633fbc1b9ee58ea6568bb1a922acd6dde0e0cd5c

    // Public key (32 bytes):
    // Hex: 4ecd8587c0471e2043839484f6c6b9e343dc6f6fa99553fde11b837e18bfd460

    // Signature for message "hello" (64 bytes):
    // Hex: b61a571468d424fa6c191a697e1a2e0e7eb2c6c25470d26a54179bee87044ea647324b975be7dc76dc40836cce9cc8a0fb0398e2392f35c3bae0364383eafa0f

    // Create test public key and signature
    let encoding = #hex({
      byteEncoding = #raw({ curve = #ed25519 });
      format = { prefix = #none };
    });
    let #ok(testPublicKey) = EdDSA.publicKeyFromText("4ecd8587c0471e2043839484f6c6b9e343dc6f6fa99553fde11b837e18bfd460", encoding) else Runtime.trap("Failed to create test public key");
    let #ok(testSignature) = EdDSA.signatureFromText("b61a571468d424fa6c191a697e1a2e0e7eb2c6c25470d26a54179bee87044ea647324b975be7dc76dc40836cce9cc8a0fb0398e2392f35c3bae0364383eafa0f", encoding) else Runtime.trap("Failed to create test signature");

    // Pre-generated serialized data for parsing benchmarks
    let publicKeyRawBytes = testPublicKey.toBytes(#raw);
    let signatureRawBytes = testSignature.toBytes(#raw);

    // Pre-generated text representations
    let publicKeyHexRaw = testPublicKey.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));
    let signatureHexRaw = testSignature.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));

    let bench = Bench.Bench();

    bench.name("EdDSA Cryptographic Operations Benchmarks");
    bench.description("Benchmark signature verification, serialization, and deserialization operations for EdDSA");

    bench.rows([
      "verification_ed25519",
      "publicKey_toBytes",
      "publicKey_fromBytes",
      "signature_toBytes",
      "signature_fromBytes",
      "publicKey_toText_hex",
      "publicKey_fromText_hex",
      "signature_toText_hex",
      "signature_fromText_hex",
    ]);

    bench.cols(["1", "10", "100"]);

    bench.runner(
      func(row, col) {
        let ?n = Nat.fromText(col) else Runtime.trap("Cols must only contain numbers: " # col);

        // Define the operation to perform based on the row
        let operation = switch (row) {
          case ("verification_ed25519") func(_ : Nat) : Result.Result<Any, Text> {
            let isValid = testPublicKey.verify(messageData.vals(), testSignature);
            if (isValid) #ok else #err("Verification failed");
          };

          case ("publicKey_toBytes") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testPublicKey.toBytes(#raw);
            #ok;
          };

          case ("publicKey_fromBytes") func(_ : Nat) : Result.Result<Any, Text> {
            EdDSA.publicKeyFromBytes(publicKeyRawBytes.vals(), #raw({ curve = #ed25519 }));
          };

          case ("signature_toBytes") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testSignature.toBytes(#raw);
            #ok;
          };

          case ("signature_fromBytes") func(_ : Nat) : Result.Result<Any, Text> {
            EdDSA.signatureFromBytes(signatureRawBytes.vals(), #raw({ curve = #ed25519 }));
          };

          case ("publicKey_toText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testPublicKey.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));
            #ok;
          };

          case ("publicKey_fromText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            EdDSA.publicKeyFromText(publicKeyHexRaw, #hex({ byteEncoding = #raw({ curve = #ed25519 }); format = { prefix = #none } }));
          };

          case ("signature_toText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            ignore testSignature.toText(#hex({ byteEncoding = #raw; format = { isUpper = false; prefix = #none } }));
            #ok;
          };

          case ("signature_fromText_hex") func(_ : Nat) : Result.Result<Any, Text> {
            EdDSA.signatureFromText(signatureHexRaw, #hex({ byteEncoding = #raw({ curve = #ed25519 }); format = { prefix = #none } }));
          };

          case (_) Runtime.trap("Unknown row: " # row);
        };

        // Single shared loop with result checking
        for (i in Nat.range(1, n + 1)) {
          switch (operation(i)) {
            case (#ok(_)) ();
            case (#err(e)) Runtime.trap(e);
          };
        };
      }
    );

    bench;
  };

};
