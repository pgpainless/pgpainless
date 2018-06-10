package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public interface DecryptionBuilderInterface {

    DecryptWith onInputStream(InputStream inputStream);

    interface DecryptWith {

        VerifyWith decryptWith(PGPSecretKeyRingCollection secretKeyRings, SecretKeyRingProtector decryptor);

        VerifyWith doNotDecrypt();

    }

    interface VerifyWith {

        MissingPublicKeyFeedback verifyWith(Set<Long> trustedFingerprints, PGPPublicKeyRingCollection publicKeyRings);

        MissingPublicKeyFeedback verifyWith(Set<Long> trustedFingerprints, Set<PGPPublicKeyRing> publicKeyRings);

        Build doNotVerify();

    }

    interface MissingPublicKeyFeedback {

        Build handleMissingPublicKeysWith(MissingPublicKeyCallback callback);

        Build ignoreMissingPublicKeys();
    }

    interface Build {

        DecryptionStream build() throws IOException, PGPException;

    }

}
