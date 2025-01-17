## PGPainless API with pgpainless-core

The `pgpainless-core` module contains the bulk of the actual OpenPGP implementation.

This is a quickstart guide. For more in-depth exploration of the API, checkout [](indepth.md).

:::{note}
This chapter is work in progress.
:::

### Setup

PGPainless' releases are published to and can be fetched from Maven Central.
To get started, you first need to include `pgpainless-core` in your projects build script:

```
// If you use Gradle
...
dependencies {
    ...
    implementation "org.pgpainless:pgpainless-core:XYZ"
    ...
}

// If you use Maven
...
<dependencies>
    ...
    <dependency>
        <groupId>org.pgpainless</groupId>
        <artifactId>pgpainless-core</artifactId>
        <version>XYZ</version>
    </dependency>
    ...
</dependencies>
```

This will automatically pull in PGPainless' dependencies, such as Bouncy Castle.

:::{important}
Replace `XYZ` with the current version, in this case {{ env.config.version }}!
:::

The entry point to the API is the `PGPainless` class.
For many common use-cases, examples can be found in the
{{ '[examples package](https://{}/main/pgpainless-core/src/test/java/org/pgpainless/example)'.format(repo_pgpainless_src) }}.
There is a very good chance that you can find code examples there that fit your needs.

### Read and Write Keys
Reading keys from ASCII armored strings or from binary files is easy:

```java
String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"...;
PGPSecretKeyRing secretKey = PGPainless.readKeyRing()
        .secretKeyRing(key);
```

Similarly, keys or certificates can quickly be exported:

```java
// ASCII armored key
PGPSecretKeyRing secretKey = ...;
String armored = PGPainless.asciiArmor(secretKey);
        
// binary (unarmored) key
byte[] binary = secretKey.getEncoded();
```

### Generate a Key
PGPainless comes with a method to quickly generate modern OpenPGP keys.
There are some predefined key archetypes, but it is possible to fully customize the key generation to fit your needs.

```java
// EdDSA primary key with EdDSA signing- and XDH encryption subkeys
PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
        .modernKeyRing("Romeo <romeo@montague.lit>", "thisIsAPassword");

// RSA key without additional subkeys
PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
        .simpleRsaKeyRing("Juliet <juliet@montague.lit>", RsaLength._4096);
```

As you can see, it is possible to generate all kinds of different keys.

### Extract a Certificate
If you have a secret key, you might want to extract a public key certificate from it:

```java
PGPSecretKeyRing secretKey = ...;
PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
```

### Apply / Remove ASCII Armor
TODO

### Encrypt a Message
TODO

### Decrypt a Message
TODO

### Sign a Message
TODO

### Verify a Signature
TODO
