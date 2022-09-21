package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.pgpainless.util.SessionKey;

public class HardwareSecurity {

    public interface DecryptionCallback {

        /**
         * Delegate decryption of a Public-Key-Encrypted-Session-Key (PKESK) to an external API for dealing with
         * hardware security modules such as smartcards or TPMs.
         *
         * If decryption fails for some reason, a subclass of the {@link HardwareSecurityException} is thrown.
         *
         * @param pkesk public-key-encrypted session key
         * @return decrypted session key
         * @throws HardwareSecurityException exception
         */
        SessionKey decryptSessionKey(PGPPublicKeyEncryptedData pkesk) throws HardwareSecurityException;

    }

    public static class HardwareSecurityException extends Exception {

    }
}
