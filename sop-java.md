# SOP-Java
The [Stateless OpenPGP Protocol (SOP)](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) specification defines a straightforward interface for common OpenPGP operations.
The Java library `sop-java` contains abstract interfaces reproducing the SOP API. This enables tight integration of OpenPGP functionality.

The point of defining the SOP protocol as an abstract Java library is to enable consumers to decouple their application from the used OpenPGP backend.

In the example below, replacing the backend would accomplished simply by swapping out the first line.

## Usage Examples
```java
SOP sop = new FooSOP();

// Generate an OpenPGP key
// This needs to be kept secret
byte[] key = sop.generateKey()
        .userId("Alice <alice@example.org>")
        .generate()
        .getBytes();

// Extract the certificate (public key)
// This can be published and shared with others
byte[] cert = sop.extractCert()
        .key(key)
        .getBytes();

// Encrypt a message
byte[] bobsCert = ...
byte[] message = ...
byte[] encrypted = sop.encrypt()
        .withCert(cert)
        .withCert(bobsCert)
        .signWith(key)
        .plaintext(message)
        .getBytes();

// Decrypt a message
ByteArrayAndResult<DecryptionResult> messageAndVerifications = sop.decrypt()
        .verifyWith(cert)
        .withKey(key)
        .ciphertext(encrypted)
        .toByteArrayAndResult();
byte[] decrypted = messageAndVerifications.getBytes();

// Signature Verifications
DecryptionResult messageInfo = messageAndVerifications.getResult();
List<Verification> signatureVerifications = messageInfo.getVerifications();
```


## Known Implementations
`PGPainless` provides an implementation of the `sop-java` library, named `pgpainless-sop`. Unsurprisingly, this library makes use of `pgpainless-core` to implement `sop-java`.

## CLI
If you need a command line interface for your `sop-java` implementation, see [sop-java-picocli](sop-java-picocli.html).