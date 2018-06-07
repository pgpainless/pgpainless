package de.vanitasvitae.crypto.pgpainless.key;

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;

public interface SecretKeyRingProtector {

   PBESecretKeyDecryptor getDecryptor(Long keyId);

   PBESecretKeyEncryptor getEncryptor(Long keyId);

}
