/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.vanitasvitae.crypto.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.glass.ui.Window;
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
    private MissingPublicKeyCallback missingPublicKeyCallback = null;

    @Override
    public DecryptWith onInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
        return new DecryptWithImpl();
    }

    class DecryptWithImpl implements DecryptWith {

        @Override
        public VerifyWith decryptWith(SecretKeyRingProtector decryptor, PGPSecretKeyRingCollection secretKeyRings) {
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
                PGPPublicKeyRing p = i.next();
                if (trustedKeyIds.contains(p.getPublicKey().getKeyID())) {
                    publicKeyRings.add(p);
                }
            }
            return verifyWith(publicKeyRings);
        }

        @Override
        public MissingPublicKeyFeedback verifyWith(Set<PGPPublicKeyRing> publicKeyRings) {
            DecryptionBuilder.this.verificationKeys = publicKeyRings;
            return new MissingPublicKeyFeedbackImpl();
        }

        @Override
        public Build doNotVerify() {
            DecryptionBuilder.this.verificationKeys = null;
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
        public DecryptionStream build() throws IOException, PGPException {
            return DecryptionStreamFactory.create(inputStream,
                    decryptionKeys, decryptionKeyDecryptor, verificationKeys, missingPublicKeyCallback);
        }
    }
}
