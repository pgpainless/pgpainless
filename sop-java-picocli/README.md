# SOP-Java-Picocli

Implementation of the [Stateless OpenPGP Command Line Interface](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01) specification.
This terminal application allows generation of OpenPGP keys, extraction of public key certificates,
armoring and de-armoring of data, as well as - of course - encryption/decryption of messages and creation/verification of signatures.

## Install a SOP backend

This module comes without a SOP backend, so in order to function you need to extend it with an implementation of the interfaces defined in `sop-java`.
An implementation using PGPainless can be found in the module `pgpainless-sop`, but it is of course possible to provide your
own implementation.

Just install your SOP backend by calling 
```java
// static method call prior to execution of the main method
SopCLI.setSopInstance(yourSopImpl);
```

## Usage

To get an overview of available commands of the application, execute
```shell
java -jar sop-java-picocli-XXX.jar help
```

If you just want to get started encrypting messages, see the module `pgpainless-cli` which initializes
`sop-java-picocli` with `pgpainless-sop`, so you can get started right away without the need to manually wire stuff up.

Enjoy!