package de.vanitasvitae.crypto.pgpainless;

import de.vanitasvitae.crypto.pgpainless.decryption_verification.DecryptionBuilder;
import de.vanitasvitae.crypto.pgpainless.encryption_signing.EncryptionBuilder;
import de.vanitasvitae.crypto.pgpainless.key.generation.KeyRingBuilder;

public class PGPainless {

    public static KeyRingBuilder generateKeyRing() {
        return new KeyRingBuilder();
    }

    public static EncryptionBuilder createEncryptor() {
        return new EncryptionBuilder();
    }

    public static DecryptionBuilder createDecryptor() {
        return new DecryptionBuilder();
    }

}
