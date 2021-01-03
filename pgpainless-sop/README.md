# PGPainless-SOP

PGPainless-SOP is an implementation of the [Stateless OpenPGP Command Line Interface](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01) specification based on PGPainless.

## Build
To build an executable, `gradle jar` should be sufficient. The resulting jar file can be found in `pgpainless-sop/build/libs/`.

## Execute
You can now use the jar file like described in the stateless OpenPGP cli document.

An example call may look like this:
```
java -jar pgpainless-sop-X.X.X.jar generate-key "Alice <alice@wonderland.lit>"
```

To discover all commands use
```
java -jar pgpainless-sop-X.X.X.jar help
```

Enjoy!
