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
package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class DecryptionBuilder implements DecryptionBuilderInterface {

    private InputStream inputStream;
    private PGPSecretKeyRingCollection decryptionKeys;
    private SecretKeyRingProtector decryptionKeyDecryptor;
    private Passphrase decryptionPassphrase;
    private List<PGPSignature> detachedSignatures;
    private Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private MissingPublicKeyCallback missingPublicKeyCallback = null;

    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    @Override
    public DecryptWith onInputStream(@Nonnull InputStream inputStream) {
        this.inputStream = inputStream;
        return new DecryptWithImpl();
    }

    class DecryptWithImpl implements DecryptWith {

        @Override
        public Verify decryptWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection secretKeyRings) {
            DecryptionBuilder.this.decryptionKeys = secretKeyRings;
            DecryptionBuilder.this.decryptionKeyDecryptor = decryptor;
            return new VerifyImpl();
        }

        @Override
        public Verify decryptWith(@Nonnull Passphrase passphrase) {
            if (passphrase.isEmpty()) {
                throw new IllegalArgumentException("Passphrase MUST NOT be empty.");
            }
            DecryptionBuilder.this.decryptionPassphrase = passphrase;
            return new VerifyImpl();
        }

        @Override
        public Verify doNotDecrypt() {
            DecryptionBuilder.this.decryptionKeys = null;
            DecryptionBuilder.this.decryptionKeyDecryptor = null;
            return new VerifyImpl();
        }
    }

    class VerifyImpl implements Verify {

        @Override
        public VerifyWith verifyDetachedSignature(@Nonnull InputStream inputStream) throws IOException, PGPException {
            List<PGPSignature> signatures = new ArrayList<>();
            InputStream pgpIn = PGPUtil.getDecoderStream(inputStream);
            PGPObjectFactory objectFactory = new PGPObjectFactory(
                    pgpIn, keyFingerPrintCalculator);
            Object nextObject = objectFactory.nextObject();
            while (nextObject != null) {
                if (nextObject instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData) nextObject;
                    objectFactory = new PGPObjectFactory(compressedData.getDataStream(), keyFingerPrintCalculator);
                    nextObject = objectFactory.nextObject();
                    continue;
                }
                if (nextObject instanceof PGPSignatureList) {
                    PGPSignatureList signatureList = (PGPSignatureList) nextObject;
                    for (PGPSignature s : signatureList) {
                        signatures.add(s);
                    }
                }
                if (nextObject instanceof PGPSignature) {
                    signatures.add((PGPSignature) nextObject);
                }
                nextObject = objectFactory.nextObject();
            }
            pgpIn.close();
            return verifyDetachedSignatures(signatures);
        }

        @Override
        public VerifyWith verifyDetachedSignatures(@Nonnull List<PGPSignature> signatures) {
            DecryptionBuilder.this.detachedSignatures = signatures;
            return new VerifyWithImpl();
        }

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRingCollection publicKeyRings) {
            return new VerifyWithImpl().verifyWith(publicKeyRings);
        }

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull Set<OpenPgpV4Fingerprint> trustedFingerprints,
                                                  @Nonnull PGPPublicKeyRingCollection publicKeyRings) {
            return new VerifyWithImpl().verifyWith(trustedFingerprints, publicKeyRings);
        }

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull Set<PGPPublicKeyRing> publicKeyRings) {
            return new VerifyWithImpl().verifyWith(publicKeyRings);
        }

        @Override
        public Build doNotVerify() {
            DecryptionBuilder.this.verificationKeys = null;
            return new BuildImpl();
        }
    }

    class VerifyWithImpl implements VerifyWith {

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = new HashSet<>();
            for (Iterator<PGPPublicKeyRing> i = publicKeyRingCollection.getKeyRings(); i.hasNext(); ) {
                publicKeyRings.add(i.next());
            }
            return verifyWith(publicKeyRings);
        }

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull Set<OpenPgpV4Fingerprint> trustedKeyIds,
                                                  @Nonnull PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = keyRingCollectionToSet(publicKeyRingCollection);
            removeUntrustedPublicKeys(publicKeyRings, trustedKeyIds);
            return verifyWith(publicKeyRings);
        }

        private void removeUntrustedPublicKeys(Set<PGPPublicKeyRing> publicKeyRings, Set<OpenPgpV4Fingerprint> trustedKeyIds) {
            for (PGPPublicKeyRing p : new HashSet<>(publicKeyRings)) {
                if (!trustedKeyIds.contains(new OpenPgpV4Fingerprint(p))) {
                    publicKeyRings.remove(p);
                }
            }
        }

        private Set<PGPPublicKeyRing> keyRingCollectionToSet(PGPPublicKeyRingCollection publicKeyRingCollection) {
            Set<PGPPublicKeyRing> publicKeyRings = new HashSet<>();
            for (Iterator<PGPPublicKeyRing> i = publicKeyRingCollection.getKeyRings(); i.hasNext(); ) {
                publicKeyRings.add(i.next());
            }
            return publicKeyRings;
        }

        @Override
        public HandleMissingPublicKeys verifyWith(@Nonnull Set<PGPPublicKeyRing> publicKeyRings) {
            DecryptionBuilder.this.verificationKeys = publicKeyRings;
            return new HandleMissingPublicKeysImpl();
        }
    }

    class HandleMissingPublicKeysImpl implements HandleMissingPublicKeys {

        @Override
        public Build handleMissingPublicKeysWith(@Nonnull MissingPublicKeyCallback callback) {
            DecryptionBuilder.this.missingPublicKeyCallback = callback;
            return new BuildImpl();
        }

        @Override
        public Build ignoreMissingPublicKeys() {
            DecryptionBuilder.this.missingPublicKeyCallback = null;
            return new BuildImpl();
        }
    }

    class BuildImpl implements Build {

        @Override
        public DecryptionStream build() throws IOException, PGPException {
            return DecryptionStreamFactory.create(inputStream,
                    decryptionKeys, decryptionKeyDecryptor, decryptionPassphrase, detachedSignatures, verificationKeys, missingPublicKeyCallback);
        }
    }
}
