# Stateless OpenPGP Protocol
The [Stateless OpenPGP Protocol (SOP)](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/) specification defines a straightforward interface for commonly used OpenPGP operations.

## Java API
While the aforementioned document specifies a command line interface, shelling out to a CLI is not an ideal way of incorporating functionality into an application.
A dedicated Java API is easier to consume and less error prone.

For that reason, `sop-java` was created as a general definition of such API. `sop-java` itself does not have any dependencies on cryptographic libraries, so it is possible to 

## Command Line Application
