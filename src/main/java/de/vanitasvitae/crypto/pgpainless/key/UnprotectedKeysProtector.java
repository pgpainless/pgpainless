package de.vanitasvitae.crypto.pgpainless.key;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

/**
 * Implementation of the {@link SecretKeyRingProtector} which assumes that all handled keys are not password protected.
 */
public class UnprotectedKeysProtector implements SecretKeyRingProtector {
    @Override
    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        return null;
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(Long keyId) {
        return null;
    }
}
