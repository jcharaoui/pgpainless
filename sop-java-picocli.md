# SOP-Java-Picocli

`sop-java-picocli` provides a command line interface frontend for SOP implementations.

## Example Implementation
In order to enable OpenPGP operations, you need to set an implementation of [`sop-java`](sop-java.html):
```java
public class MySOPCLI {
    public static void main(String[] args) {
        // Set your own SOP backend
        SOP mySOP = new MySOP();
        SopCLI.setSopInstance(mySOP);

        // Forward the main method
        SopCLI.main(args);
    }
}
```

## Usage
```bash
$ ./sop-java-picocli help
Usage: sop-java-picocli [COMMAND]
Stateless OpenPGP Protocol
Commands:
  help                                 Displays help information about the
                                         specified command
  armor                                Add ASCII Armor to standard input
  dearmor                              Remove ASCII Armor from standard input
  decrypt                              Decrypt a message from standard input
  detach-inband-signature-and-message  Split a clearsigned message
  encrypt                              Encrypt a message from standard input
  extract-cert                         Extract a public key certificate from a
                                         secret key from standard input
  generate-key                         Generate a secret key
  sign                                 Create a detached signature on the data
                                         from standard input
  verify                               Verify a detached signature over the
                                         data from standard input
  version                              Display version information about the
                                         tool
Exit Codes:
   0   Successful program execution
   1   Generic program error
   3   Verification requested but no verifiable signature found
  13   Unsupported asymmetric algorithm
  17   Certificate is not encryption capable
  19   Usage error: Missing argument
  23   Incomplete verification instructions
  29   Unable to decrypt
  31   Password is not human-readable
  37   Unsupported Option
  41   Invalid data or data of wrong type encountered
  53   Non-text input received where text was expected
  59   Output file already exists
  61   Input file does not exist
  67   Key is password protected
  69   Unsupported subcommand
  71   Unsupported special prefix (e.g. "@env/@fd") of indirect parameter
  73   Ambiguous input (a filename matching the designator already exists)
```

### Generate a Key (Secret Key)
```bash
$ ./sop-java-picocli generage-key "Alice <alice@example.org>" > key.asc
```

### Extract a Certificate (Public Key)
```bash
$ ./sop-java-picocli extract-cert < key.asc > cert.asc
```

### Encrypt a Message
```bash
$ ./sop-java-picocli encrypt --sign-with=key.asc cert.asc < message.txt > message.asc
```

### Decrypt a Message
```bash
$ ./sop-java-picocli decrypt --verify-with=cert.asc --verify-out=verifications.txt key.asc < message.asc > message.txt
$ cat verifications.txt
```

### Create a Detached Signature
```bash
$ ./sop-java-picocli sign key.asc < message.txt > message.txt.sig
```

### Verify a Detached Signature
```bash
$ ./sop-java-picocli verify message.txt.sig cert.asc < message.txt
```