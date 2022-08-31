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
interface.
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

The last example shows how to instantiate the `CachingSecretKeyRingProtector` with a `SecretKeyPassphraseProvider`.
As the name suggests, the `CachingSecretKeyRingProtector` caches passphrases in a map.
If you try to unlock a protected secret key for which no passphrase is cached, the `getPassphraseFor()` method of
the `SecretKeyPassphraseProvider` will be called to interactively ask for the missing passphrase. Afterwards, the
acquired passphrase will be cached for future use.

Most `SecretKeyRingProtector` implementations can be instantiated with custom `KeyRingProtectionSettings`.
By default, most implementations use `KeyRingProtectionSettings.secureDefaultSettings()` which corresponds to iterated
and salted S2K using AES256 and SHA256 with an iteration count of 65536.
