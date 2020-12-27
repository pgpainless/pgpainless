package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtector2 {

    PBESecretKeyDecryptor getDecryptor(PGPSecretKey key) throws PGPException;

    PBESecretKeyEncryptor getEncryptor(PGPSecretKey key) throws PGPException;
}
