import { test } "mo:test";
import Runtime "mo:new-base/Runtime";
import PublicKey "../src/PublicKey";
import Text "mo:base/Text";
import Principal "mo:base/Principal";

test(
  "Ed25519 PublicKey Creation and Equality",
  func() {
    // Test vector: public key bytes
    let pubKeyBytes : [Nat8] = [
      29,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];

    // Create a public key
    let publicKey = PublicKey.PublicKey(pubKeyBytes);

    // Test equality with identical key
    let publicKey2 = PublicKey.PublicKey(pubKeyBytes);
    assert (publicKey.equal(publicKey2));

    // Test equality with different key
    let differentBytes : [Nat8] = [
      30,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];
    let differentKey = PublicKey.PublicKey(differentBytes);
    assert (not publicKey.equal(differentKey));
  },
);

test(
  "PublicKey to/fromBytes (raw)",
  func() {
    // Test vector: public key bytes
    let pubKeyBytes : [Nat8] = [
      29,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];

    // Create a public key
    let publicKey = PublicKey.PublicKey(pubKeyBytes);

    // Export to raw bytes
    let rawBytes = publicKey.toBytes(#raw);
    assert (rawBytes == pubKeyBytes);

    // Import from raw bytes
    let importedKey = switch (PublicKey.fromBytes(rawBytes.vals(), #raw)) {
      case (#ok(key)) key;
      case (#err(e)) Runtime.trap("Failed to import key: " # e);
    };

    // Check equality
    assert (publicKey.equal(importedKey));
  },
);

test(
  "PublicKey to/fromBytes (SPKI)",
  func() {
    // Test vector: public key bytes
    let pubKeyBytes : [Nat8] = [
      29,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];

    // Create a public key
    let publicKey = PublicKey.PublicKey(pubKeyBytes);

    // Export to SPKI bytes
    let spkiBytes = publicKey.toBytes(#spki);

    // Import from SPKI bytes
    let importedKey = switch (PublicKey.fromBytes(spkiBytes.vals(), #spki)) {
      case (#ok(key)) key;
      case (#err(e)) Runtime.trap("Failed to import key: " # e);
    };

    // Check equality
    assert (publicKey.equal(importedKey));
  },
);

test(
  "PublicKey to/fromText (formats)",
  func() {
    // Test vector: public key bytes
    let pubKeyBytes : [Nat8] = [
      29,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];

    // Create a public key
    let publicKey = PublicKey.PublicKey(pubKeyBytes);

    // Define formats to test
    type FormatPair = {
      outputFormat : PublicKey.OutputTextFormat;
      inputFormat : PublicKey.InputTextFormat;
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
        outputFormat = #pem({
          byteEncoding = #spki;
        });
        inputFormat = #pem({
          byteEncoding = #spki;
        });
      },
      {
        outputFormat = #hex({
          byteEncoding = #spki;
          format = { isUpper = true; prefix = #single("0x") };
        });
        inputFormat = #hex({
          byteEncoding = #spki;
          format = { prefix = #single("0x") };
        });
      },
    ];

    // Test each format for roundtrip conversion
    for (format in formats.vals()) {
      let text = publicKey.toText(format.outputFormat);

      let importedKey = switch (PublicKey.fromText(text, format.inputFormat)) {
        case (#ok(key)) key;
        case (#err(e)) Runtime.trap("Failed to import key from " # debug_show (format) # ": " # e);
      };

      // Check equality
      assert (publicKey.equal(importedKey));
    };
  },
);

test(
  "PublicKey to Principal conversion",
  func() {
    // Test vector: public key bytes
    let pubKeyBytes : [Nat8] = [
      29,
      94,
      233,
      153,
      210,
      232,
      188,
      142,
      220,
      159,
      196,
      122,
      84,
      66,
      176,
      139,
      186,
      251,
      104,
      90,
      78,
      239,
      213,
      9,
      58,
      48,
      96,
      220,
      186,
      160,
      14,
      15,
    ];

    // Create a public key
    let publicKey = PublicKey.PublicKey(pubKeyBytes);

    // Convert to Principal
    let principal = publicKey.toPrincipal();

    // We can only verify that conversion doesn't trap and returns a Principal
    // The specific Principal value would depend on the implementation details
    assert (Text.startsWith(Principal.toText(principal), #text("2")));
  },
);

test(
  "PublicKey Error Handling",
  func() {
    // Test with invalid key size
    let invalidBytes : [Nat8] = [1, 2, 3]; // Too short

    let result = PublicKey.fromBytes(invalidBytes.vals(), #raw);
    switch (result) {
      case (#ok(_)) Runtime.trap("Should have failed with invalid key size");
      case (#err(e)) assert (Text.startsWith(e, #text("Invalid Ed25519 public key size")));
    };

    // Test with invalid SPKI format
    let invalidSpki : [Nat8] = [0x30, 0x01, 0x00]; // Invalid ASN.1

    let result2 = PublicKey.fromBytes(invalidSpki.vals(), #spki);
    switch (result2) {
      case (#ok(_)) Runtime.trap("Should have failed with invalid SPKI format");
      case (#err(_)) (); // Expected error, specific message is ASN.1 library dependent
    };

    // Test with invalid hex
    let invalidHex = "not a hex string";

    let result3 = PublicKey.fromText(
      invalidHex,
      #hex({
        byteEncoding = #raw;
        format = { prefix = #none };
      }),
    );

    switch (result3) {
      case (#ok(_)) Runtime.trap("Should have failed with invalid hex");
      case (#err(_)) (); // Expected error
    };
  },
);
