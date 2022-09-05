# Passwords

In Java based applications, passing passwords as `String` objects has the
[disadvantage](https://stackoverflow.com/a/8881376/11150851) that you have to rely on garbage collection to clean up
once they are no longer used.
For that reason, `char[]` is the preferred method for dealing with passwords.
Once a password is no longer used, the character array can simply be overwritten to remove the sensitive data from
memory.

## Passphrase
PGPainless uses a wrapper class `Passphrase`, which takes care for the wiping of unused passwords:

```java
Passphrase passphrase = new Passphrase(new char[] {'h', 'e', 'l', 'l', 'o'});
assertTrue(passphrase.isValid());

assertArrayEquals(new char[] {'h', 'e', 'l', 'l', 'o'}, passphrase.getChars()):

// Once we are done, we can clean the data
passphrase.clear();

assertFalse(passphrase.isValid());
assertNull(passphrase.getChars());
```

Furthermore, `Passphrase` can also wrap empty passphrases, which increases null-safety of the API:

```java
Passphrase empty = Passphrase.emptyPassphrase();
assertTrue(empty.isValid());
assertTrue(empty.isEmpty());
assertNull(empty.getChars());

empty.clear();

assertFalse(empty.isValid());
```

## SecretKeyRingProtector

There are certain operations that require you to provide the passphrase for a key.
Examples are decryption of messages, or creating signatures / certifications.

The primary way of telling PGPainless, which password to use for a certain key is the `SecretKeyRingProtector`
interface which maps `Passphrases` to (sub-)keys.
There are multiple implementations of this interface, which may or may not suite your needs:

```java
// If your key is not password protected, this implementation is for you:
SecretKeyRingProtector unprotected = SecretKeyRingProtector
        .unprotectedKeys();

// If you use a single passphrase for all (sub-) keys, take this:
SecretKeyRingProtector singlePassphrase = SecretKeyRingProtector
        .unlockAnyKeyWith(passphrase);

// If you want to be flexible, use this:
CachingSecretKeyRingProtector flexible = SecretKeyRingProtector
        .defaultSecretKeyRingProtector(passphraseCallback);
```

`SecretKeyRingProtector.unprotectedKeys()` will return an empty passphrase for any key.
It is best used when dealing with unencrypted secret keys.

`SecretKeyRingProtector.unlockAnyKeyWith(passphrase)` will return the same exact passphrase for any given key.
You should use this if you have a single key with a static passphrase.

The last example shows how to instantiate the `CachingSecretKeyRingProtector` with a `SecretKeyPassphraseProvider`
as argument.
As the name suggests, the `CachingSecretKeyRingProtector` caches passphrases it knows about in a map.
That way, you only have to provide the passphrase for a certain key only once, after which it will be remembered.
If you try to unlock a protected secret key for which no passphrase is cached, the `getPassphraseFor()` method of
the `SecretKeyPassphraseProvider` callback will be called to interactively ask for the missing passphrase.
Afterwards, the acquired passphrase will be cached for future use.

:::{note}
While especially the `CachingSecretKeyRingProtector` can handle multiple keys without problems, it is advised
to use individual `SecretKeyRingProtector` objects per key.
The reason for this is, that internally the 64bit key-id is used to resolve `Passphrase` objects and collisions are not
unlikely in this key-space.
Furthermore, multiple OpenPGP keys could contain the same subkey, but with different passphrases set.
If the same `SecretKeyRingProtector` is used for two OpenPGP keys with the same subkey, but different passwords,
the key-id collision will cause the password to be overwritten for one of the keys, which might result in issues.
See `FLO-04-004 WP2` of the [2021 security audit](https://cure53.de/pentest-report_pgpainless.pdf) for more details.
:::

Most `SecretKeyRingProtector` implementations can be instantiated with custom `KeyRingProtectionSettings`.
By default, most implementations use `KeyRingProtectionSettings.secureDefaultSettings()` which corresponds to iterated
and salted S2K using AES256 and SHA256 with an iteration count of 65536.
