package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PainlessResult;
import de.vanitasvitae.crypto.pgpainless.encryption_signing.SecretKeyRingDecryptor;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public interface DecryptionBuilderInterface {

    DecryptWith onInputStream(InputStream inputStream);

    interface DecryptWith {

        VerifyWith decryptWith(PGPSecretKeyRingCollection secretKeyRings, SecretKeyRingDecryptor decryptor);

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

        PainlessResult.ResultAndInputStream build() throws IOException, PGPException;

    }

}
