package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.PainlessResult;
import de.vanitasvitae.crypto.pgpainless.key.SecretKeyRingProtector;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public class DecryptionBuilder implements DecryptionBuilderInterface {

    private InputStream inputStream;
    private PGPSecretKeyRingCollection decryptionKeys;
    private SecretKeyRingProtector decryptionKeyDecryptor;
    private Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private Set<Long> trustedKeyIds = new HashSet<>();
    private MissingPublicKeyCallback missingPublicKeyCallback = null;

    @Override
    public DecryptWith onInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
        return new DecryptWithImpl();
    }

    class DecryptWithImpl implements DecryptWith {

        @Override
        public VerifyWith decryptWith(PGPSecretKeyRingCollection secretKeyRings, SecretKeyRingProtector decryptor) {
            DecryptionBuilder.this.decryptionKeys = secretKeyRings;
            DecryptionBuilder.this.decryptionKeyDecryptor = decryptor;
            return new VerifyWithImpl();
        }

        @Override
        public VerifyWith doNotDecrypt() {
            DecryptionBuilder.this.decryptionKeys = null;
            DecryptionBuilder.this.decryptionKeyDecryptor = null;
            return new VerifyWithImpl();
        }
    }

    class VerifyWithImpl implements VerifyWith {

        @Override
        public MissingPublicKeyFeedback verifyWith(Set<Long> trustedKeyIds,
                                                   PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = new HashSet<>();
            for (Iterator<PGPPublicKeyRing> i = publicKeyRingCollection.getKeyRings(); i.hasNext(); ) {
                publicKeyRings.add(i.next());
            }
            return verifyWith(trustedKeyIds, publicKeyRings);
        }

        @Override
        public MissingPublicKeyFeedback verifyWith(Set<Long> trustedKeyIds, Set<PGPPublicKeyRing> publicKeyRings) {
            DecryptionBuilder.this.verificationKeys = publicKeyRings;
            DecryptionBuilder.this.trustedKeyIds = trustedKeyIds;
            return new MissingPublicKeyFeedbackImpl();
        }

        @Override
        public Build doNotVerify() {
            DecryptionBuilder.this.verificationKeys = null;
            DecryptionBuilder.this.trustedKeyIds = null;
            return new BuildImpl();
        }
    }

    class MissingPublicKeyFeedbackImpl implements MissingPublicKeyFeedback {

        @Override
        public Build handleMissingPublicKeysWith(MissingPublicKeyCallback callback) {
            DecryptionBuilder.this.missingPublicKeyCallback = callback;
            return new BuildImpl();
        }

        @Override
        public Build ignoreMissingPublicKeys() {
            return new BuildImpl();
        }
    }

    class BuildImpl implements Build {

        @Override
        public PainlessResult.ResultAndInputStream build() throws IOException, PGPException {
            return DecryptionStreamFactory.create(inputStream,
                    decryptionKeys, decryptionKeyDecryptor, verificationKeys, trustedKeyIds, missingPublicKeyCallback);
        }
    }
}
