package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingDecryptor {

   PBESecretKeyDecryptor getDecryptor(Long keyId);

   PBESecretKeyEncryptor getEncryptor(Long keyId);

}
