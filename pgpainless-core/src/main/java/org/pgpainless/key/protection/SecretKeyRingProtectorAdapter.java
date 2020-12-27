package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtectorAdapter extends SecretKeyRingProtector, SecretKeyRingProtector2 {

    @Override
    default PBESecretKeyDecryptor getDecryptor(PGPSecretKey key) throws PGPException {
        return getDecryptor(key.getKeyID());
    }

    @Override
    default PBESecretKeyEncryptor getEncryptor(PGPSecretKey key) throws PGPException {
        return getEncryptor(key.getKeyID());
    }
}
