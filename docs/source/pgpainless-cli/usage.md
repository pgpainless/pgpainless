# User Guide PGPainless-CLI

The module `pgpainless-cli` contains a command line application which conforms to the
[Stateless OpenPGP Command Line Interface](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/).

You can use it to generate keys, encrypt, sign and decrypt messages, as well as verify signatures.

## Implementation

Essentially, `pgpainless-cli` is just a very small composing module, which injects `pgpainless-sop` as a
concrete implementation of `sop-java` into `sop-java-picocli`.

## Install

The `pgpainless-cli` command line application is available in Debian unstable / Ubuntu 22.10 and can be installed via APT:
```shell
$ sudo apt install pgpainless-cli
```

This method comes with man-pages:
```shell
$ man pgpainless-cli
```

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
  help           Display usage information for the specified subcommand
  armor          Add ASCII Armor to standard input
  dearmor        Remove ASCII Armor from standard input
  decrypt        Decrypt a message from standard input
  inline-detach  Split signatures from a clearsigned message
  encrypt        Encrypt a message from standard input
  extract-cert   Extract a public key certificate from a secret key from
                   standard input
  generate-key   Generate a secret key
  sign           Create a detached signature on the data from standard input
  verify         Verify a detached signature over the data from standard input
  inline-sign    Create an inline-signed message from data on standard input
  inline-verify  Verify inline-signed data from standard input
  version        Display version information about the tool

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