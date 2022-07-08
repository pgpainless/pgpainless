# User Guide PGPainless-CLI

The module `pgpainless-cli` contains a command line application which conforms to the
[Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/).

You can use it to generate keys, encrypt, sign and decrypt messages, as well as verify signatures.

## Implementation

Essentially, `pgpainless-cli` is just a very small composing module, which injects `pgpainless-sop` as a
concrete implementation of `sop-java` into `sop-java-picocli`.

## Build

To build a standalone *fat*-jar:
```shell
$ cd pgpainless-cli/
$ gradle shadowJar
```

The fat-jar can afterwards be found in `build/libs/`.

To build a [distributable](https://docs.gradle.org/current/userguide/distribution_plugin.html):

```shell
$ cd pgpainless-cli/
$ gradle installDist
```

Afterwards, an uncompressed distributable is installed in `build/install/`.
To execute the application, you can call `build/install/bin/pgpainless-cli{.bat}`

## Usage

Hereafter, the program will be referred to as `pgpainless-cli`.

```
$ pgpainless-cli help
Stateless OpenPGP Protocol
Usage: pgpainless-cli [COMMAND]

Commands:
  help           Stateless OpenPGP Protocol
  armor          Stateless OpenPGP Protocol
  dearmor        Stateless OpenPGP Protocol
  decrypt        Stateless OpenPGP Protocol
  inline-detach  Stateless OpenPGP Protocol
  encrypt        Stateless OpenPGP Protocol
  extract-cert   Stateless OpenPGP Protocol
  generate-key   Stateless OpenPGP Protocol
  sign           Stateless OpenPGP Protocol
  verify         Stateless OpenPGP Protocol
  inline-sign    Stateless OpenPGP Protocol
  inline-verify  Stateless OpenPGP Protocol
  version        Stateless OpenPGP Protocol

Exit Codes:
   0   Successful program execution.
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
  67   Cannot unlock password protected secret key
  69   Unsupported subcommand
  71   Unsupported special prefix (e.g. "@env/@fd") of indirect parameter
  73   Ambiguous input (a filename matching the designator already exists)
  79   Key is not signing capable
Powered by picocli
```