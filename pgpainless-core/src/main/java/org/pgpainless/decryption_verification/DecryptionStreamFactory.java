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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public final class DecryptionStreamFactory {

    private static final Logger LOGGER = Logger.getLogger(DecryptionStreamFactory.class.getName());
    private static final Level LEVEL = Level.FINE;

    private final PGPSecretKeyRingCollection decryptionKeys;
    private final SecretKeyRingProtector decryptionKeyDecryptor;
    private final Set<PGPPublicKeyRing> verificationKeys = new HashSet<>();
    private final MissingPublicKeyCallback missingPublicKeyCallback;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private final PGPContentVerifierBuilderProvider verifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();
    private final KeyFingerPrintCalculator keyFingerprintCalculator = new BcKeyFingerprintCalculator();
    private final Map<OpenPgpV4Fingerprint, OnePassSignature> verifiableOnePassSignatures = new HashMap<>();

    private DecryptionStreamFactory(@Nullable PGPSecretKeyRingCollection decryptionKeys,
                                    @Nullable SecretKeyRingProtector decryptor,
                                    @Nullable Set<PGPPublicKeyRing> verificationKeys,
                                    @Nullable MissingPublicKeyCallback missingPublicKeyCallback) {
        this.decryptionKeys = decryptionKeys;
        this.decryptionKeyDecryptor = decryptor;
        this.verificationKeys.addAll(verificationKeys != null ? verificationKeys : Collections.emptyList());
        this.missingPublicKeyCallback = missingPublicKeyCallback;
    }

    public static DecryptionStream create(@Nonnull InputStream inputStream,
                                          @Nullable PGPSecretKeyRingCollection decryptionKeys,
                                          @Nullable SecretKeyRingProtector decryptor,
                                          @Nullable List<PGPSignature> detachedSignatures,
                                          @Nullable Set<PGPPublicKeyRing> verificationKeys,
                                          @Nullable MissingPublicKeyCallback missingPublicKeyCallback)
            throws IOException, PGPException {
        InputStream pgpInputStream;
        DecryptionStreamFactory factory = new DecryptionStreamFactory(decryptionKeys, decryptor, verificationKeys,
                missingPublicKeyCallback);

        if (detachedSignatures != null) {
            pgpInputStream = inputStream;
            for (PGPSignature signature : detachedSignatures) {
                PGPPublicKey signingKey = factory.findSignatureVerificationKey(signature.getKeyID());
                signature.init(new BcPGPContentVerifierBuilderProvider(), signingKey);
                factory.resultBuilder.addDetachedSignature(
                        new DetachedSignature(signature, new OpenPgpV4Fingerprint(signingKey)));
            }
        } else {
            PGPObjectFactory objectFactory = new PGPObjectFactory(
                    PGPUtil.getDecoderStream(inputStream), new BcKeyFingerprintCalculator());
            pgpInputStream = factory.processPGPPackets(objectFactory);
        }
        return new DecryptionStream(pgpInputStream, factory.resultBuilder);
    }

    private InputStream processPGPPackets(@Nonnull PGPObjectFactory objectFactory) throws IOException, PGPException {
        Object nextPgpObject;
        while ((nextPgpObject = objectFactory.nextObject()) != null) {
            if (nextPgpObject instanceof PGPEncryptedDataList) {
                return processPGPEncryptedDataList((PGPEncryptedDataList) nextPgpObject);
            }
            if (nextPgpObject instanceof PGPCompressedData) {
                return processPGPCompressedData((PGPCompressedData) nextPgpObject);
            }
            if (nextPgpObject instanceof PGPOnePassSignatureList) {
                return processOnePassSignatureList(objectFactory, (PGPOnePassSignatureList) nextPgpObject);
            }
            if (nextPgpObject instanceof PGPLiteralData) {
                return processPGPLiteralData(objectFactory, (PGPLiteralData) nextPgpObject);
            }
        }

        throw new PGPException("No Literal Data Packet found");
    }

    private InputStream processPGPEncryptedDataList(PGPEncryptedDataList pgpEncryptedDataList)
            throws PGPException, IOException {
        LOGGER.log(LEVEL, "Encountered PGPEncryptedDataList");
        InputStream decryptedDataStream = decrypt(pgpEncryptedDataList);
        return processPGPPackets(new PGPObjectFactory(PGPUtil.getDecoderStream(decryptedDataStream), keyFingerprintCalculator));
    }

    private InputStream processPGPCompressedData(PGPCompressedData pgpCompressedData)
            throws PGPException, IOException {
        CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.fromId(pgpCompressedData.getAlgorithm());
        LOGGER.log(LEVEL, "Encountered PGPCompressedData: " + compressionAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);

        InputStream dataStream = pgpCompressedData.getDataStream();
        PGPObjectFactory objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(dataStream), keyFingerprintCalculator);

        return processPGPPackets(objectFactory);
    }

    private InputStream processOnePassSignatureList(@Nonnull PGPObjectFactory objectFactory, PGPOnePassSignatureList onePassSignatures)
            throws PGPException, IOException {
        LOGGER.log(LEVEL, "Encountered PGPOnePassSignatureList of size " + onePassSignatures.size());
        initOnePassSignatures(onePassSignatures);
        return processPGPPackets(objectFactory);
    }

    private InputStream processPGPLiteralData(@Nonnull PGPObjectFactory objectFactory, PGPLiteralData pgpLiteralData) {
        LOGGER.log(LEVEL, "Found PGPLiteralData");
        InputStream literalDataInputStream = pgpLiteralData.getInputStream();

        if (verifiableOnePassSignatures.isEmpty()) {
            LOGGER.log(LEVEL, "No OnePassSignatures found -> We are done");
            return literalDataInputStream;
        }

        return new SignatureVerifyingInputStream(literalDataInputStream,
                objectFactory, verifiableOnePassSignatures, resultBuilder);
    }

    private InputStream decrypt(@Nonnull PGPEncryptedDataList encryptedDataList)
            throws PGPException {
        Iterator<?> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
        if (!encryptedDataIterator.hasNext()) {
            throw new PGPException("Decryption failed - EncryptedDataList has no items");
        }

        PGPPrivateKey decryptionKey = null;
        PGPPublicKeyEncryptedData encryptedSessionKey = null;
        while (encryptedDataIterator.hasNext()) {
            PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();
            long keyId = encryptedData.getKeyID();

            resultBuilder.addRecipientKeyId(keyId);
            LOGGER.log(LEVEL, "PGPEncryptedData is encrypted for key " + Long.toHexString(keyId));

            PGPSecretKey secretKey = decryptionKeys.getSecretKey(keyId);
            if (secretKey != null) {
                LOGGER.log(LEVEL, "Found respective secret key " + Long.toHexString(keyId));
                // Watch out! This assignment is possibly done multiple times.
                encryptedSessionKey = encryptedData;
                decryptionKey = secretKey.extractPrivateKey(decryptionKeyDecryptor.getDecryptor(keyId));
                resultBuilder.setDecryptionFingerprint(new OpenPgpV4Fingerprint(secretKey));
            }
        }

        if (decryptionKey == null) {
            throw new PGPException("Decryption failed - No suitable decryption key found");
        }

        PublicKeyDataDecryptorFactory keyDecryptor = new BcPublicKeyDataDecryptorFactory(decryptionKey);
        SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm
                .fromId(encryptedSessionKey.getSymmetricAlgorithm(keyDecryptor));

        LOGGER.log(LEVEL, "Message is encrypted using " + symmetricKeyAlgorithm);
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

        resultBuilder.setIntegrityProtected(encryptedSessionKey.isIntegrityProtected());

        return encryptedSessionKey.getDataStream(keyDecryptor);
    }

    private void initOnePassSignatures(@Nonnull PGPOnePassSignatureList onePassSignatureList) throws PGPException {
        Iterator<PGPOnePassSignature> iterator = onePassSignatureList.iterator();
        if (!iterator.hasNext()) {
            throw new PGPException("Verification failed - No OnePassSignatures found");
        }

        processOnePassSignatures(iterator);
    }

    private void processOnePassSignatures(Iterator<PGPOnePassSignature> signatures) throws PGPException {
        while (signatures.hasNext()) {
            PGPOnePassSignature signature = signatures.next();
            processOnePassSignature(signature);
        }
    }

    private void processOnePassSignature(PGPOnePassSignature signature) throws PGPException {
        final long keyId = signature.getKeyID();

        LOGGER.log(LEVEL, "Message contains OnePassSignature from " + Long.toHexString(keyId));

        // Find public key
        PGPPublicKey verificationKey = findSignatureVerificationKey(keyId);
        if (verificationKey == null) {
            LOGGER.log(LEVEL, "Missing verification key from " + Long.toHexString(keyId));
            return;
        }

        signature.init(verifierBuilderProvider, verificationKey);
        OnePassSignature onePassSignature = new OnePassSignature(signature, new OpenPgpV4Fingerprint(verificationKey));
        resultBuilder.addOnePassSignature(onePassSignature);
        verifiableOnePassSignatures.put(new OpenPgpV4Fingerprint(verificationKey), onePassSignature);
    }

    private PGPPublicKey findSignatureVerificationKey(long keyId) {
        PGPPublicKey verificationKey = null;
        for (PGPPublicKeyRing publicKeyRing : verificationKeys) {
            verificationKey = publicKeyRing.getPublicKey(keyId);
            if (verificationKey != null) {
                LOGGER.log(LEVEL, "Found public key " + Long.toHexString(keyId) + " for signature verification");
                break;
            }
        }

        if (verificationKey == null) {
            verificationKey = handleMissingVerificationKey(keyId);
        }

        return verificationKey;
    }

    private PGPPublicKey handleMissingVerificationKey(long keyId) {
        LOGGER.log(Level.FINER, "No public key found for signature of " + Long.toHexString(keyId));

        if (missingPublicKeyCallback == null) {
            LOGGER.log(Level.FINER, "No MissingPublicKeyCallback registered. " +
                    "Skip signature of " + Long.toHexString(keyId));
            return null;
        }

        PGPPublicKey missingPublicKey = missingPublicKeyCallback.onMissingPublicKeyEncountered(keyId);
        if (missingPublicKey == null) {
            LOGGER.log(Level.FINER, "MissingPublicKeyCallback did not provider key. " +
                    "Skip signature of " + Long.toHexString(keyId));
            return null;
        }

        if (missingPublicKey.getKeyID() != keyId) {
            throw new IllegalArgumentException("KeyID of the provided public key differs from the signatures keyId. " +
                    "The signature was created from " + Long.toHexString(keyId) + " while the provided key has ID " +
                    Long.toHexString(missingPublicKey.getKeyID()));
        }

        return missingPublicKey;
    }

}
