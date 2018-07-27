PGPainless is a wrapper around [Bouncycastle](https://www.bouncycastle.org/), which provides an easy to use, intuitive, but also powerful API for OpenPGP. Its main functionality is encrypting, signing, decrypting and verifying data, as well as generating encryption keys.

Note, that the project is still in alpha phase.

## About
PGPainless was created [during a Google Summer of Code project](https://vanitasvitae.github.io/GSOC2018/), for which an easy to use OpenPGP API for Java and Android was needed. Originally the author looked into forking [bouncy-gpg](https://github.com/neuhalje/bouncy-gpg), but since support for lower Android versions was a requirement, PGPainless was born as an independent project. The library is however heavily influenced by bouncy-gpg.

### Easy to use API

One main focus of the project is ease of use. Using Bouncycastle can be a hassle, since simple tasks require a substantial amount of boilerplate code and small mistakes are easily made. PGPainless aims at providing a simple interface to get the job done quickly, while not trading away functionality.

### Android Support
PGPainless is designed to work on Android versions down to [API level 9](https://developer.android.com/about/versions/android-2.3) (Gingerbread). This makes PGPainless a good choice for implementing OpenPGP encryption in your Android app.

Compatibility with certain Android APIs is ensured through [Animalsniffer](http://www.mojohaus.org/animal-sniffer/).

## Releases
PGPainless is released on the maven central repository. Including it in your project is simple:

Maven:
```xml
<dependency>
    <groupId>org.pgpainless</groupId>
    <artifactId>pgpainless-core</artifactId>
    <version>0.0.1-alpha2</version>
</dependency>
```

Gradle:
```gradle
repositories {
	mavenCentral()
}

dependencies {
	compile 'org.pgpainless:pgpainless-core:0.0.1-alpha2'
}
```

There are also [snapshot releases](https://oss.sonatype.org/content/repositories/snapshots/org/pgpainless/pgpainless-core/)  available.

## Development
PGPainless is currently developed by [@vanitasvitae](https://vanitasvitae.github.io).

### Contribute
Contributions are always welcome :) The project is developed in the following places:
* [Github](https://github.com/pgpainless/pgpainless)
* [Teahub](https://teahub.io/pgpainless/pgpainless)

Pull requests are accepted on either of them.

### Bug Reports
PGPainless is in a *very* early state of development and the likelihood of bugs is quite high. If you encounter a bug, please make sure to check, whether the bug has already been reported either [here](https://github.com/pgpainless/pgpainless/issues), or [here](https://teahub.io/PGPainless/pgpainless/issues), in order to avoid duplicate bug reports.
