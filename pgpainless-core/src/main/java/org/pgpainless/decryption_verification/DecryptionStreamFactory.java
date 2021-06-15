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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.MissingLiteralDataException;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.DetachedSignature;
import org.pgpainless.signature.OnePassSignature;
import org.pgpainless.util.IntegrityProtectedInputStream;
import org.pgpainless.util.Passphrase;

public final class DecryptionStreamFactory {

    private static final Logger LOGGER = Logger.getLogger(DecryptionStreamFactory.class.getName());
    private static final Level LEVEL = Level.FINE;
    private static final int MAX_RECURSION_DEPTH = 16;

    private final ConsumerOptions options;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private static final PGPContentVerifierBuilderProvider verifierBuilderProvider = ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider();
    private static final KeyFingerPrintCalculator keyFingerprintCalculator = ImplementationFactory.getInstance().getKeyFingerprintCalculator();
    private final Map<OpenPgpV4Fingerprint, OnePassSignature> verifiableOnePassSignatures = new HashMap<>();
    private final List<IntegrityProtectedInputStream> integrityProtectedStreams = new ArrayList<>();

    public DecryptionStreamFactory(ConsumerOptions options) {
        this.options = options;
    }

    public static DecryptionStream create(@Nonnull InputStream inputStream,
                                          @Nonnull ConsumerOptions options)
            throws PGPException, IOException {
        BufferedInputStream bufferedIn = new BufferedInputStream(inputStream);
        bufferedIn.mark(200);
        DecryptionStreamFactory factory = new DecryptionStreamFactory(options);

        for (PGPSignature signature : options.getDetachedSignatures()) {
            PGPPublicKeyRing signingKeyRing = factory.findSignatureVerificationKeyRing(signature.getKeyID());
            if (signingKeyRing == null) {
                continue;
            }
            PGPPublicKey signingKey = signingKeyRing.getPublicKey(signature.getKeyID());
            signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
            factory.resultBuilder.addDetachedSignature(
                    new DetachedSignature(signature, signingKeyRing, new SubkeyIdentifier(signingKeyRing, signature.getKeyID())));
        }

        PGPObjectFactory objectFactory = new PGPObjectFactory(
                PGPUtil.getDecoderStream(bufferedIn), keyFingerprintCalculator);

        try {
            // Parse OpenPGP message
            inputStream = factory.processPGPPackets(objectFactory, 1);
        } catch (MissingLiteralDataException e) {
            // Not an OpenPGP message. Reset the buffered stream to parse the message as arbitrary binary data
            //  to allow for detached signature verification.
            bufferedIn.reset();
            inputStream = bufferedIn;
        }

        return new DecryptionStream(inputStream, factory.resultBuilder, factory.integrityProtectedStreams);
    }

    private InputStream processPGPPackets(@Nonnull PGPObjectFactory objectFactory, int depth) throws IOException, PGPException {
        if (depth >= MAX_RECURSION_DEPTH) {
            throw new PGPException("Maximum recursion depth of packages exceeded.");
        }
        Object nextPgpObject;
        while ((nextPgpObject = objectFactory.nextObject()) != null) {
            if (nextPgpObject instanceof PGPEncryptedDataList) {
                return processPGPEncryptedDataList((PGPEncryptedDataList) nextPgpObject, depth);
            }
            if (nextPgpObject instanceof PGPCompressedData) {
                return processPGPCompressedData((PGPCompressedData) nextPgpObject, depth);
            }
            if (nextPgpObject instanceof PGPOnePassSignatureList) {
                return processOnePassSignatureList(objectFactory, (PGPOnePassSignatureList) nextPgpObject, depth);
            }
            if (nextPgpObject instanceof PGPLiteralData) {
                return processPGPLiteralData(objectFactory, (PGPLiteralData) nextPgpObject);
            }
        }

        throw new MissingLiteralDataException("No Literal Data Packet found");
    }

    private InputStream processPGPEncryptedDataList(PGPEncryptedDataList pgpEncryptedDataList, int depth)
            throws PGPException, IOException {
        LOGGER.log(LEVEL, "Encountered PGPEncryptedDataList");
        InputStream decryptedDataStream = decrypt(pgpEncryptedDataList);
        return processPGPPackets(new PGPObjectFactory(PGPUtil.getDecoderStream(decryptedDataStream), keyFingerprintCalculator), ++depth);
    }

    private InputStream processPGPCompressedData(PGPCompressedData pgpCompressedData, int depth)
            throws PGPException, IOException {
        CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.fromId(pgpCompressedData.getAlgorithm());
        LOGGER.log(LEVEL, "Encountered PGPCompressedData: " + compressionAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);

        InputStream dataStream = pgpCompressedData.getDataStream();
        PGPObjectFactory objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(dataStream), keyFingerprintCalculator);

        return processPGPPackets(objectFactory, ++depth);
    }

    private InputStream processOnePassSignatureList(@Nonnull PGPObjectFactory objectFactory, PGPOnePassSignatureList onePassSignatures, int depth)
            throws PGPException, IOException {
        LOGGER.log(LEVEL, "Encountered PGPOnePassSignatureList of size " + onePassSignatures.size());
        initOnePassSignatures(onePassSignatures);
        return processPGPPackets(objectFactory, ++depth);
    }

    private InputStream processPGPLiteralData(@Nonnull PGPObjectFactory objectFactory, PGPLiteralData pgpLiteralData) {
        LOGGER.log(LEVEL, "Found PGPLiteralData");
        InputStream literalDataInputStream = pgpLiteralData.getInputStream();
        OpenPgpMetadata.FileInfo fileInfo = new OpenPgpMetadata.FileInfo(
                pgpLiteralData.getFileName(),
                pgpLiteralData.getModificationTime(),
                StreamEncoding.fromCode(pgpLiteralData.getFormat()));
        resultBuilder.setFileInfo(fileInfo);

        if (verifiableOnePassSignatures.isEmpty()) {
            LOGGER.log(LEVEL, "No OnePassSignatures found -> We are done");
            return literalDataInputStream;
        }

        return new SignatureVerifyingInputStream(literalDataInputStream,
                objectFactory, verifiableOnePassSignatures, resultBuilder);
    }

    private InputStream decrypt(@Nonnull PGPEncryptedDataList encryptedDataList)
            throws PGPException {
        Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
        if (!encryptedDataIterator.hasNext()) {
            throw new PGPException("Decryption failed - EncryptedDataList has no items");
        }

        PGPPrivateKey decryptionKey = null;
        PGPPublicKeyEncryptedData encryptedSessionKey = null;
        while (encryptedDataIterator.hasNext()) {
            PGPEncryptedData encryptedData = encryptedDataIterator.next();

            // TODO: Can we just skip non-integrity-protected packages?
            if (!encryptedData.isIntegrityProtected()) {
                throw new MessageNotIntegrityProtectedException();
            }

            // Data is passphrase encrypted
            if (encryptedData instanceof PGPPBEEncryptedData) {
                PGPPBEEncryptedData pbeEncryptedData = (PGPPBEEncryptedData) encryptedData;
                for (Passphrase passphrase : options.getDecryptionPassphrases()) {
                    PBEDataDecryptorFactory passphraseDecryptor = ImplementationFactory.getInstance()
                            .getPBEDataDecryptorFactory(passphrase);
                    try {
                        InputStream decryptedDataStream = pbeEncryptedData.getDataStream(passphraseDecryptor);

                        SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.fromId(
                                pbeEncryptedData.getSymmetricAlgorithm(passphraseDecryptor));
                        throwIfAlgorithmIsRejected(symmetricKeyAlgorithm);
                        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

                        return decryptedDataStream;
                    } catch (PGPException e) {
                        LOGGER.log(LEVEL, "Probable passphrase mismatch, skip PBE encrypted data block", e);
                    }
                }
            }

            // data is public key encrypted
            else if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                if (options.getDecryptionKeys().isEmpty()) {

                }
                PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                long keyId = publicKeyEncryptedData.getKeyID();
                if (!options.getDecryptionKeys().isEmpty()) {
                    // Known key id
                    if (keyId != 0) {
                        LOGGER.log(LEVEL, "PGPEncryptedData is encrypted for key " + Long.toHexString(keyId));
                        resultBuilder.addRecipientKeyId(keyId);
                        PGPSecretKeyRing decryptionKeyRing = findDecryptionKeyRing(keyId);
                        if (decryptionKeyRing != null) {
                            PGPSecretKey secretKey = decryptionKeyRing.getSecretKey(keyId);
                            LOGGER.log(LEVEL, "Found respective secret key " + Long.toHexString(keyId));
                            // Watch out! This assignment is possibly done multiple times.
                            encryptedSessionKey = publicKeyEncryptedData;
                            decryptionKey = UnlockSecretKey.unlockSecretKey(secretKey, options.getSecretKeyProtector(decryptionKeyRing));
                            resultBuilder.setDecryptionFingerprint(new OpenPgpV4Fingerprint(secretKey));
                        }
                    }

                    // Hidden recipient
                    else {
                        LOGGER.log(LEVEL, "Hidden recipient detected. Try to decrypt with all available secret keys.");
                        outerloop: for (PGPSecretKeyRing ring : options.getDecryptionKeys()) {
                            KeyRingInfo info = new KeyRingInfo(ring);
                            List<PGPPublicKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS);
                            for (PGPPublicKey pubkey : encryptionSubkeys) {
                                PGPSecretKey key = ring.getSecretKey(pubkey.getKeyID());
                                if (key == null) {
                                    continue;
                                }

                                PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(key, options.getSecretKeyProtector(ring).getDecryptor(key.getKeyID()));
                                PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance().getPublicKeyDataDecryptorFactory(privateKey);
                                try {
                                    publicKeyEncryptedData.getSymmetricAlgorithm(decryptorFactory); // will only succeed if we have the right secret key
                                    LOGGER.log(LEVEL, "Found correct key " + Long.toHexString(key.getKeyID()) + " for hidden recipient decryption.");
                                    decryptionKey = privateKey;
                                    resultBuilder.setDecryptionFingerprint(new OpenPgpV4Fingerprint(key));
                                    encryptedSessionKey = publicKeyEncryptedData;
                                    break outerloop;
                                } catch (PGPException | ClassCastException e) {
                                    LOGGER.log(LEVEL, "Skipping wrong key " + Long.toHexString(key.getKeyID()) + " for hidden recipient decryption.", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        return decryptWith(encryptedSessionKey, decryptionKey);
    }

    private InputStream decryptWith(PGPPublicKeyEncryptedData encryptedSessionKey, PGPPrivateKey decryptionKey)
            throws PGPException {
        if (decryptionKey == null) {
            throw new MissingDecryptionMethodException("Decryption failed - No suitable decryption key or passphrase found");
        }

        PublicKeyDataDecryptorFactory dataDecryptor = ImplementationFactory.getInstance()
                .getPublicKeyDataDecryptorFactory(decryptionKey);

        SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm
                .fromId(encryptedSessionKey.getSymmetricAlgorithm(dataDecryptor));
        if (symmetricKeyAlgorithm == SymmetricKeyAlgorithm.NULL) {
            LOGGER.log(LEVEL, "Message is unencrypted");
        } else {
            LOGGER.log(LEVEL, "Message is encrypted using " + symmetricKeyAlgorithm);
        }
        throwIfAlgorithmIsRejected(symmetricKeyAlgorithm);
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

        IntegrityProtectedInputStream integrityProtected =
                new IntegrityProtectedInputStream(encryptedSessionKey.getDataStream(dataDecryptor), encryptedSessionKey);
        integrityProtectedStreams.add(integrityProtected);
        return integrityProtected;
    }

    private void throwIfAlgorithmIsRejected(SymmetricKeyAlgorithm algorithm) throws UnacceptableAlgorithmException {
        if (!PGPainless.getPolicy().getSymmetricKeyDecryptionAlgoritmPolicy().isAcceptable(algorithm)) {
            throw new UnacceptableAlgorithmException("Data is "
                    + (algorithm == SymmetricKeyAlgorithm.NULL ? "unencrypted" : "encrypted with symmetric algorithm " + algorithm) + " which is not acceptable as per PGPainless' policy.\n" +
                    "To mark this algorithm as acceptable, use PGPainless.getPolicy().setSymmetricKeyDecryptionAlgorithmPolicy().");
        }
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
        PGPPublicKeyRing verificationKeyRing = findSignatureVerificationKeyRing(keyId);
        if (verificationKeyRing == null) {
            LOGGER.log(LEVEL, "Missing verification key from " + Long.toHexString(keyId));
            return;
        }
        PGPPublicKey verificationKey = verificationKeyRing.getPublicKey(keyId);

        signature.init(verifierBuilderProvider, verificationKey);
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(verificationKey);
        OnePassSignature onePassSignature = new OnePassSignature(signature, verificationKeyRing);
        resultBuilder.addOnePassSignature(onePassSignature);
        verifiableOnePassSignatures.put(fingerprint, onePassSignature);
    }

    private PGPSecretKeyRing findDecryptionKeyRing(long keyId) {
        for (PGPSecretKeyRing key : options.getDecryptionKeys()) {
            if (key.getSecretKey(keyId) != null) {
                return key;
            }
        }
        return null;
    }

    private PGPPublicKeyRing findSignatureVerificationKeyRing(long keyId) {
        PGPPublicKeyRing verificationKeyRing = null;
        for (PGPPublicKeyRing publicKeyRing : options.getCertificates()) {
            PGPPublicKey verificationKey = publicKeyRing.getPublicKey(keyId);
            if (verificationKey != null) {
                LOGGER.log(LEVEL, "Found public key " + Long.toHexString(keyId) + " for signature verification");
                verificationKeyRing = publicKeyRing;
                break;
            }
        }

        if (verificationKeyRing == null && options.getMissingCertificateCallback() != null) {
            verificationKeyRing = options.getMissingCertificateCallback().onMissingPublicKeyEncountered(keyId);
        }

        return verificationKeyRing;
    }
}
