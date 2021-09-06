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
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredInputStream;
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
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.DetachedSignature;
import org.pgpainless.signature.OnePassSignature;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.CRCingArmoredInputStreamWrapper;
import org.pgpainless.util.IntegrityProtectedInputStream;
import org.pgpainless.util.Passphrase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DecryptionStreamFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptionStreamFactory.class);
    private static final int MAX_RECURSION_DEPTH = 16;

    private final ConsumerOptions options;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private static final PGPContentVerifierBuilderProvider verifierBuilderProvider =
            ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider();
    private static final KeyFingerPrintCalculator keyFingerprintCalculator =
            ImplementationFactory.getInstance().getKeyFingerprintCalculator();
    private final Map<OpenPgpV4Fingerprint, OnePassSignature> verifiableOnePassSignatures = new HashMap<>();
    private IntegrityProtectedInputStream integrityProtectedEncryptedInputStream;

    public DecryptionStreamFactory(ConsumerOptions options) {
        this.options = options;
        initializeDetachedSignatures(options.getDetachedSignatures());
    }

    private void initializeDetachedSignatures(Set<PGPSignature> signatures) {
        for (PGPSignature signature : signatures) {
            long issuerKeyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing signingKeyRing = findSignatureVerificationKeyRing(issuerKeyId);
            if (signingKeyRing == null) {
                continue;
            }
            PGPPublicKey signingKey = signingKeyRing.getPublicKey(issuerKeyId);
            SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(signingKeyRing, signingKey.getKeyID());
            try {
                signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);
                resultBuilder.addDetachedSignature(
                        new DetachedSignature(signature, signingKeyRing, signingKeyIdentifier));
            } catch (PGPException e) {
                LOGGER.warn("Cannot verify detached signature made by {}. Reason: {}", signingKeyIdentifier, e.getMessage(), e);
            }
        }
    }

    public static DecryptionStream create(@Nonnull InputStream inputStream,
                                          @Nonnull ConsumerOptions options)
            throws PGPException, IOException {
        BufferedInputStream bufferedIn = new BufferedInputStream(inputStream);
        bufferedIn.mark(200);
        DecryptionStreamFactory factory = new DecryptionStreamFactory(options);

        InputStream decoderStream = PGPUtil.getDecoderStream(bufferedIn);
        decoderStream = CRCingArmoredInputStreamWrapper.possiblyWrap(decoderStream);

        if (decoderStream instanceof ArmoredInputStream) {
            ArmoredInputStream armor = (ArmoredInputStream) decoderStream;

            if (armor.isClearText()) {
                throw new WrongConsumingMethodException("Message appears to be using the Cleartext Signature Framework. " +
                        "Use PGPainless.verifyCleartextSignedMessage() to verify this message instead.");
            }
        }

        PGPObjectFactory objectFactory = new PGPObjectFactory(
                decoderStream, keyFingerprintCalculator);

        try {
            // Parse OpenPGP message
            inputStream = factory.processPGPPackets(objectFactory, 1);
        } catch (EOFException e) {
            throw e;
        }
        catch (MissingLiteralDataException e) {
            // Not an OpenPGP message.
            //  Reset the buffered stream to parse the message as arbitrary binary data
            //  to allow for detached signature verification.
            LOGGER.debug("The message appears to not be an OpenPGP message. This is probably data signed with detached signatures?");
            bufferedIn.reset();
            inputStream = bufferedIn;
        } catch (IOException e) {
            if (e.getMessage().contains("invalid armor")) {
                // We falsely assumed the data to be armored.
                LOGGER.debug("The message is apparently not armored.");
                bufferedIn.reset();
                inputStream = bufferedIn;
            } else {
                throw e;
            }
        }

        return new DecryptionStream(inputStream, options, factory.resultBuilder, factory.integrityProtectedEncryptedInputStream,
                (decoderStream instanceof ArmoredInputStream) ? decoderStream : null);
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
                return processPGPLiteralData(objectFactory, (PGPLiteralData) nextPgpObject, depth);
            }
        }

        throw new MissingLiteralDataException("No Literal Data Packet found");
    }

    private InputStream processPGPEncryptedDataList(PGPEncryptedDataList pgpEncryptedDataList, int depth)
            throws PGPException, IOException {
        LOGGER.debug("Depth {}: Encountered PGPEncryptedDataList", depth);
        InputStream decryptedDataStream = decrypt(pgpEncryptedDataList);
        InputStream decodedDataStream = PGPUtil.getDecoderStream(decryptedDataStream);
        PGPObjectFactory factory = new PGPObjectFactory(decodedDataStream, keyFingerprintCalculator);
        return processPGPPackets(factory, ++depth);
    }

    private InputStream processPGPCompressedData(PGPCompressedData pgpCompressedData, int depth)
            throws PGPException, IOException {
        CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.fromId(pgpCompressedData.getAlgorithm());
        LOGGER.debug("Depth {}: Encountered PGPCompressedData: {}", depth, compressionAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);

        InputStream inflatedDataStream = pgpCompressedData.getDataStream();
        InputStream decodedDataStream = PGPUtil.getDecoderStream(inflatedDataStream);
        PGPObjectFactory objectFactory = new PGPObjectFactory(decodedDataStream, keyFingerprintCalculator);

        return processPGPPackets(objectFactory, ++depth);
    }

    private InputStream processOnePassSignatureList(@Nonnull PGPObjectFactory objectFactory, PGPOnePassSignatureList onePassSignatures, int depth)
            throws PGPException, IOException {
        LOGGER.debug("Depth {}: Encountered PGPOnePassSignatureList of size {}", depth, onePassSignatures.size());
        initOnePassSignatures(onePassSignatures);
        return processPGPPackets(objectFactory, ++depth);
    }

    private InputStream processPGPLiteralData(@Nonnull PGPObjectFactory objectFactory, PGPLiteralData pgpLiteralData, int depth) {
        LOGGER.debug("Depth {}: Found PGPLiteralData", depth);
        InputStream literalDataInputStream = pgpLiteralData.getInputStream();

        resultBuilder.setFileName(pgpLiteralData.getFileName())
                .setModificationDate(pgpLiteralData.getModificationTime())
                .setFileEncoding(StreamEncoding.fromCode(pgpLiteralData.getFormat()));

        if (verifiableOnePassSignatures.isEmpty()) {
            LOGGER.debug("No OnePassSignatures found -> We are done");
            return literalDataInputStream;
        }

        return new SignatureVerifyingInputStream(literalDataInputStream,
                objectFactory, verifiableOnePassSignatures, options, resultBuilder);
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

                        integrityProtectedEncryptedInputStream = new IntegrityProtectedInputStream(decryptedDataStream, pbeEncryptedData);

                        return integrityProtectedEncryptedInputStream;
                    } catch (PGPException e) {
                        LOGGER.debug("Probable passphrase mismatch, skip PBE encrypted data block", e);
                    }
                }
            }

            // data is public key encrypted
            else if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;
                long keyId = publicKeyEncryptedData.getKeyID();
                if (!options.getDecryptionKeys().isEmpty()) {
                    // Known key id
                    if (keyId != 0) {
                        LOGGER.debug("PGPEncryptedData is encrypted for key {}", Long.toHexString(keyId));
                        resultBuilder.addRecipientKeyId(keyId);
                        PGPSecretKeyRing decryptionKeyRing = findDecryptionKeyRing(keyId);
                        if (decryptionKeyRing != null) {
                            PGPSecretKey secretKey = decryptionKeyRing.getSecretKey(keyId);
                            LOGGER.debug("Found respective secret key {}", Long.toHexString(keyId));
                            // Watch out! This assignment is possibly done multiple times.
                            encryptedSessionKey = publicKeyEncryptedData;
                            decryptionKey = UnlockSecretKey.unlockSecretKey(secretKey, options.getSecretKeyProtector(decryptionKeyRing));
                            resultBuilder.setDecryptionKey(new SubkeyIdentifier(decryptionKeyRing, decryptionKey.getKeyID()));
                        }
                    }

                    // Hidden recipient
                    else {
                        LOGGER.debug("Hidden recipient detected. Try to decrypt with all available secret keys.");
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
                                    LOGGER.debug("Found correct key {} for hidden recipient decryption.", Long.toHexString(key.getKeyID()));
                                    decryptionKey = privateKey;
                                    resultBuilder.setDecryptionKey(new SubkeyIdentifier(ring, decryptionKey.getKeyID()));
                                    encryptedSessionKey = publicKeyEncryptedData;
                                    break outerloop;
                                } catch (PGPException | ClassCastException e) {
                                    LOGGER.debug("Skipping wrong key {} for hidden recipient decryption.", Long.toHexString(key.getKeyID()), e);
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
            LOGGER.debug("Message is unencrypted");
        } else {
            LOGGER.debug("Message is encrypted using {}", symmetricKeyAlgorithm);
        }
        throwIfAlgorithmIsRejected(symmetricKeyAlgorithm);
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

        integrityProtectedEncryptedInputStream = new IntegrityProtectedInputStream(encryptedSessionKey.getDataStream(dataDecryptor), encryptedSessionKey);
        return integrityProtectedEncryptedInputStream;
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

        LOGGER.debug("Message contains OnePassSignature from {}", Long.toHexString(keyId));

        // Find public key
        PGPPublicKeyRing verificationKeyRing = findSignatureVerificationKeyRing(keyId);
        if (verificationKeyRing == null) {
            LOGGER.debug("Missing verification key from {}", Long.toHexString(keyId));
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
                LOGGER.debug("Found public key {} for signature verification", Long.toHexString(keyId));
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
