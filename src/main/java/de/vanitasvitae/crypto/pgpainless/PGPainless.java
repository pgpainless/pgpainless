package de.vanitasvitae.crypto.pgpainless;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import de.vanitasvitae.crypto.pgpainless.decryption_verification.DecryptionBuilder;
import de.vanitasvitae.crypto.pgpainless.encryption_signing.EncryptionBuilder;
import de.vanitasvitae.crypto.pgpainless.key.generation.KeyRingBuilder;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

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

    public static PGPPublicKeyRing publicKeyRingFromBytes(byte[] bytes) throws IOException {
        return new PGPPublicKeyRing(new ArmoredInputStream(new ByteArrayInputStream(bytes)), new BcKeyFingerprintCalculator());
    }
}
