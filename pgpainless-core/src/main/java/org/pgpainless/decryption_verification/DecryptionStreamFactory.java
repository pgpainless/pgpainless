// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
import org.pgpainless.exception.MissingPassphraseException;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.exception.WrongConsumingMethodException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.DetachedSignatureCheck;
import org.pgpainless.signature.OnePassSignatureCheck;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.CRCingArmoredInputStreamWrapper;
import org.pgpainless.util.PGPUtilWrapper;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DecryptionStreamFactory {


    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptionStreamFactory.class);
    private static final int MAX_RECURSION_DEPTH = 16;

    private final ConsumerOptions options;
    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private final List<OnePassSignatureCheck> onePassSignatureChecks = new ArrayList<>();
    private final List<DetachedSignatureCheck> detachedSignatureChecks = new ArrayList<>();
    private final Map<Long, OnePassSignatureCheck> onePassSignaturesWithMissingCert = new HashMap<>();

    private static final PGPContentVerifierBuilderProvider verifierBuilderProvider =
            ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider();
    private static final KeyFingerPrintCalculator keyFingerprintCalculator =
            ImplementationFactory.getInstance().getKeyFingerprintCalculator();
    private IntegrityProtectedInputStream integrityProtectedEncryptedInputStream;


    public static DecryptionStream create(@Nonnull InputStream inputStream,
                                          @Nonnull ConsumerOptions options)
            throws PGPException, IOException {
        DecryptionStreamFactory factory = new DecryptionStreamFactory(options);
        return factory.parseOpenPGPDataAndCreateDecryptionStream(inputStream);
    }

    public DecryptionStreamFactory(ConsumerOptions options) {
        this.options = options;
        initializeDetachedSignatures(options.getDetachedSignatures());
    }

    private void initializeDetachedSignatures(Set<PGPSignature> signatures) {
        for (PGPSignature signature : signatures) {
            long issuerKeyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing signingKeyRing = findSignatureVerificationKeyRing(issuerKeyId);
            if (signingKeyRing == null) {
                SignatureValidationException ex = new SignatureValidationException("Missing verification certificate " + Long.toHexString(issuerKeyId));
                resultBuilder.addInvalidDetachedSignature(new SignatureVerification(signature, null), ex);
                continue;
            }
            PGPPublicKey signingKey = signingKeyRing.getPublicKey(issuerKeyId);
            SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(signingKeyRing, signingKey.getKeyID());
            try {
                signature.init(verifierBuilderProvider, signingKey);
                DetachedSignatureCheck detachedSignature = new DetachedSignatureCheck(signature, signingKeyRing, signingKeyIdentifier);
                detachedSignatureChecks.add(detachedSignature);
            } catch (PGPException e) {
                SignatureValidationException ex = new SignatureValidationException("Cannot verify detached signature made by " + signingKeyIdentifier + ".", e);
                resultBuilder.addInvalidDetachedSignature(new SignatureVerification(signature, signingKeyIdentifier), ex);
            }
        }
    }

    private DecryptionStream parseOpenPGPDataAndCreateDecryptionStream(InputStream inputStream) throws IOException, PGPException {
        // Make sure we handle armored and non-armored data properly
        BufferedInputStream bufferedIn = new BufferedInputStream(inputStream);
        InputStream decoderStream;
        PGPObjectFactory objectFactory;

        try {
            decoderStream = PGPUtilWrapper.getDecoderStream(bufferedIn);
            decoderStream = CRCingArmoredInputStreamWrapper.possiblyWrap(decoderStream);

            if (decoderStream instanceof ArmoredInputStream) {
                ArmoredInputStream armor = (ArmoredInputStream) decoderStream;

                if (armor.isClearText()) {
                    throw new WrongConsumingMethodException("Message appears to be using the Cleartext Signature Framework. " +
                            "Use PGPainless.verifyCleartextSignedMessage() to verify this message instead.");
                }
            }

            objectFactory = new PGPObjectFactory(decoderStream, keyFingerprintCalculator);
            // Parse OpenPGP message
            inputStream = processPGPPackets(objectFactory, 1);
        } catch (EOFException e) {
            throw e;
        } catch (MissingLiteralDataException e) {
            // Not an OpenPGP message.
            //  Reset the buffered stream to parse the message as arbitrary binary data
            //  to allow for detached signature verification.
            LOGGER.debug("The message appears to not be an OpenPGP message. This is probably data signed with detached signatures?");
            bufferedIn.reset();
            decoderStream = bufferedIn;
            objectFactory = new PGPObjectFactory(decoderStream, keyFingerprintCalculator);
            inputStream = wrapInVerifySignatureStream(bufferedIn, objectFactory);
        } catch (IOException e) {
            if (e.getMessage().contains("invalid armor") || e.getMessage().contains("invalid header encountered")) {
                // We falsely assumed the data to be armored.
                LOGGER.debug("The message is apparently not armored.");
                bufferedIn.reset();
                decoderStream = bufferedIn;
                objectFactory = new PGPObjectFactory(decoderStream, keyFingerprintCalculator);
                inputStream = wrapInVerifySignatureStream(bufferedIn, objectFactory);
            } else {
                throw e;
            }
        }

        return new DecryptionStream(inputStream, resultBuilder, integrityProtectedEncryptedInputStream,
                (decoderStream instanceof ArmoredInputStream) ? decoderStream : null);
    }

    private InputStream wrapInVerifySignatureStream(InputStream bufferedIn, PGPObjectFactory objectFactory) {
        return new SignatureInputStream.VerifySignatures(
                bufferedIn, objectFactory, onePassSignatureChecks,
                onePassSignaturesWithMissingCert, detachedSignatureChecks, options,
                resultBuilder);
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
        InputStream decryptedDataStream = decryptSessionKey(pgpEncryptedDataList);
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
        return processPGPPackets(objectFactory, depth);
    }

    private InputStream processPGPLiteralData(@Nonnull PGPObjectFactory objectFactory, PGPLiteralData pgpLiteralData, int depth) throws IOException {
        LOGGER.debug("Depth {}: Found PGPLiteralData", depth);
        InputStream literalDataInputStream = pgpLiteralData.getInputStream();

        resultBuilder.setFileName(pgpLiteralData.getFileName())
                .setModificationDate(pgpLiteralData.getModificationTime())
                .setFileEncoding(StreamEncoding.fromCode(pgpLiteralData.getFormat()));

        if (onePassSignatureChecks.isEmpty() && onePassSignaturesWithMissingCert.isEmpty()) {
            LOGGER.debug("No OnePassSignatures found -> We are done");
            return literalDataInputStream;
        }

        return new SignatureInputStream.VerifySignatures(literalDataInputStream, objectFactory,
                onePassSignatureChecks, onePassSignaturesWithMissingCert, detachedSignatureChecks, options, resultBuilder) {
        };
    }

    private InputStream decryptSessionKey(@Nonnull PGPEncryptedDataList encryptedDataList)
            throws PGPException {
        Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();
        if (!encryptedDataIterator.hasNext()) {
            throw new PGPException("Decryption failed - EncryptedDataList has no items");
        }

        PGPPrivateKey decryptionKey = null;
        PGPPublicKeyEncryptedData encryptedSessionKey = null;

        List<PGPPBEEncryptedData> passphraseProtected = new ArrayList<>();
        List<PGPPublicKeyEncryptedData> publicKeyProtected = new ArrayList<>();
        List<Tuple<SubkeyIdentifier, PGPPublicKeyEncryptedData>> postponedDueToMissingPassphrase = new ArrayList<>();

        // Sort PKESK and SKESK packets
        while (encryptedDataIterator.hasNext()) {
            PGPEncryptedData encryptedData = encryptedDataIterator.next();

            if (!encryptedData.isIntegrityProtected() && !options.isIgnoreMDCErrors()) {
                throw new MessageNotIntegrityProtectedException();
            }

            // SKESK
            if (encryptedData instanceof PGPPBEEncryptedData) {
                passphraseProtected.add((PGPPBEEncryptedData) encryptedData);
            }
            // PKESK
            else if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                publicKeyProtected.add((PGPPublicKeyEncryptedData) encryptedData);
            }
        }

        // Try decryption with passphrases first
        for (PGPPBEEncryptedData pbeEncryptedData : passphraseProtected) {
            for (Passphrase passphrase : options.getDecryptionPassphrases()) {
                PBEDataDecryptorFactory passphraseDecryptor = ImplementationFactory.getInstance()
                        .getPBEDataDecryptorFactory(passphrase);
                try {
                    InputStream decryptedDataStream = pbeEncryptedData.getDataStream(passphraseDecryptor);

                    SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.fromId(
                            pbeEncryptedData.getSymmetricAlgorithm(passphraseDecryptor));
                    throwIfAlgorithmIsRejected(symmetricKeyAlgorithm);
                    resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);

                    integrityProtectedEncryptedInputStream = new IntegrityProtectedInputStream(decryptedDataStream, pbeEncryptedData, options);

                    return integrityProtectedEncryptedInputStream;
                } catch (PGPException e) {
                    LOGGER.debug("Probable passphrase mismatch, skip PBE encrypted data block", e);
                }
            }
        }

        // Then try decryption with public key encryption
        for (PGPPublicKeyEncryptedData publicKeyEncryptedData : publicKeyProtected) {
            PGPPrivateKey privateKey = null;
            if (options.getDecryptionKeys().isEmpty()) {
                break;
            }

            long keyId = publicKeyEncryptedData.getKeyID();
            // Wildcard KeyID
            if (keyId == 0L) {
                LOGGER.debug("Hidden recipient detected. Try to decrypt with all available secret keys.");
                for (PGPSecretKeyRing secretKeys : options.getDecryptionKeys()) {
                    if (privateKey != null) {
                        break;
                    }
                    KeyRingInfo info = new KeyRingInfo(secretKeys);
                    List<PGPPublicKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.STORAGE_AND_COMMUNICATIONS);
                    for (PGPPublicKey pubkey : encryptionSubkeys) {
                        PGPSecretKey secretKey = secretKeys.getSecretKey(pubkey.getKeyID());
                        // Skip missing secret key
                        if (secretKey == null) {
                            continue;
                        }

                        privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData, postponedDueToMissingPassphrase, true);
                    }
                }
            }
            // Non-wildcard key-id
            else {
                LOGGER.debug("PGPEncryptedData is encrypted for key {}", Long.toHexString(keyId));
                resultBuilder.addRecipientKeyId(keyId);

                PGPSecretKeyRing secretKeys = findDecryptionKeyRing(keyId);
                if (secretKeys == null) {
                    LOGGER.debug("Missing certificate of {}. Skip.", Long.toHexString(keyId));
                    continue;
                }

                PGPSecretKey secretKey = secretKeys.getSecretKey(keyId);
                privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData, postponedDueToMissingPassphrase, true);
            }
            if (privateKey == null) {
                continue;
            }
            decryptionKey = privateKey;
            encryptedSessionKey = publicKeyEncryptedData;
            break;
        }

        // Try postponed keys with missing passphrases (will cause missing passphrase callbacks to fire)
        if (encryptedSessionKey == null) {

            if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.THROW_EXCEPTION) {
                // Non-interactive mode: Throw an exception with all locked decryption keys
                Set<SubkeyIdentifier> keyIds = new HashSet<>();
                for (Tuple<SubkeyIdentifier, ?> k : postponedDueToMissingPassphrase) {
                    keyIds.add(k.getA());
                }
                if (!keyIds.isEmpty()) {
                    throw new MissingPassphraseException(keyIds);
                }
            }
            else if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.INTERACTIVE) {
                // Interactive mode: Fire protector callbacks to get passphrases interactively
                for (Tuple<SubkeyIdentifier, PGPPublicKeyEncryptedData> missingPassphrases : postponedDueToMissingPassphrase) {
                    SubkeyIdentifier keyId = missingPassphrases.getA();
                    PGPPublicKeyEncryptedData publicKeyEncryptedData = missingPassphrases.getB();
                    PGPSecretKeyRing secretKeys = findDecryptionKeyRing(keyId.getKeyId());
                    PGPSecretKey secretKey = secretKeys.getSecretKey(keyId.getSubkeyId());

                    PGPPrivateKey privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData, postponedDueToMissingPassphrase, false);
                    if (privateKey == null) {
                        continue;
                    }

                    decryptionKey = privateKey;
                    encryptedSessionKey = publicKeyEncryptedData;
                    break;
                }
            } else {
                throw new IllegalStateException("Invalid PostponedKeysStrategy set in consumer options.");
            }

        }

        return decryptWith(encryptedSessionKey, decryptionKey);
    }

    /**
     * Try decryption of the provided public-key-encrypted-data using the given secret key.
     * If the secret key is encrypted and the secret key protector does not have a passphrase available and the boolean
     * postponeIfMissingPassphrase is true, data decryption is postponed by pushing a tuple of the encrypted data decryption key
     * identifier to the postponed list.
     *
     * This method only returns a non-null private key, if the private key is able to decrypt the message successfully.
     *
     * @param secretKeys secret key ring
     * @param secretKey secret key
     * @param publicKeyEncryptedData encrypted data which is tried to decrypt using the secret key
     * @param postponed list of postponed decryptions due to missing secret key passphrases
     * @param postponeIfMissingPassphrase flag to specify whether missing secret key passphrases should result in postponed decryption
     * @return private key if decryption is successful, null if decryption is unsuccessful or postponed
     *
     * @throws PGPException in case of an OpenPGP error
     */
    private PGPPrivateKey tryPublicKeyDecryption(
            PGPSecretKeyRing secretKeys,
            PGPSecretKey secretKey,
            PGPPublicKeyEncryptedData publicKeyEncryptedData,
            List<Tuple<SubkeyIdentifier, PGPPublicKeyEncryptedData>> postponed,
            boolean postponeIfMissingPassphrase) throws PGPException {
        SecretKeyRingProtector protector = options.getSecretKeyProtector(secretKeys);

        if (postponeIfMissingPassphrase && !protector.hasPassphraseFor(secretKey.getKeyID())) {
            // Postpone decryption with key with missing passphrase
            SubkeyIdentifier identifier = new SubkeyIdentifier(secretKeys, secretKey.getKeyID());
            postponed.add(new Tuple<>(identifier, publicKeyEncryptedData));
            return null;
        }

        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(
                secretKey, protector.getDecryptor(secretKey.getKeyID()));

        // test if we have the right private key
        PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                .getPublicKeyDataDecryptorFactory(privateKey);
        try {
            publicKeyEncryptedData.getSymmetricAlgorithm(decryptorFactory); // will only succeed if we have the right secret key
            LOGGER.debug("Found correct decryption key {}.", Long.toHexString(secretKey.getKeyID()));
            resultBuilder.setDecryptionKey(new SubkeyIdentifier(secretKeys, privateKey.getKeyID()));
            return privateKey;
        } catch (PGPException | ClassCastException e) {
            return null;
        }
    }

    private InputStream decryptWith(PGPPublicKeyEncryptedData encryptedSessionKey, PGPPrivateKey decryptionKey)
            throws PGPException {
        if (decryptionKey == null || encryptedSessionKey == null) {
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

        integrityProtectedEncryptedInputStream = new IntegrityProtectedInputStream(encryptedSessionKey.getDataStream(dataDecryptor), encryptedSessionKey, options);
        return integrityProtectedEncryptedInputStream;
    }

    private void throwIfAlgorithmIsRejected(SymmetricKeyAlgorithm algorithm) throws UnacceptableAlgorithmException {
        if (!PGPainless.getPolicy().getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(algorithm)) {
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

        LOGGER.debug("Encountered OnePassSignature from {}", Long.toHexString(keyId));

        // Find public key
        PGPPublicKeyRing verificationKeyRing = findSignatureVerificationKeyRing(keyId);
        if (verificationKeyRing == null) {
            onePassSignaturesWithMissingCert.put(keyId, new OnePassSignatureCheck(signature, null));
            return;
        }
        PGPPublicKey verificationKey = verificationKeyRing.getPublicKey(keyId);

        signature.init(verifierBuilderProvider, verificationKey);
        OnePassSignatureCheck onePassSignature = new OnePassSignatureCheck(signature, verificationKeyRing);
        onePassSignatureChecks.add(onePassSignature);
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
