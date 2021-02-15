# PGPainless-SOP

PGPainless-SOP is an implementation of the [Stateless OpenPGP Command Line Interface](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01) specification based on PGPainless.

## Build
To build an executable, `gradle jar` should be sufficient. The resulting jar file can be found in `pgpainless-sop/build/libs/`.

## Execute

Simply use the provided `./pgpainless` script to execute PGPainless' Stateless Command Line Interface.

To discover all commands use
```
./pgpainless help
```

Enjoy!
