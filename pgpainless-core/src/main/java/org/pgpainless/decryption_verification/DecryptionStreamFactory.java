// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

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
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.exception.FinalIOException;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.MissingLiteralDataException;
import org.pgpainless.exception.MissingPassphraseException;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.DetachedSignatureCheck;
import org.pgpainless.signature.consumer.OnePassSignatureCheck;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.SessionKey;
import org.pgpainless.util.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class DecryptionStreamFactory {


    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptionStreamFactory.class);
    // Maximum nesting depth of packets (e.g. compression, encryption...)
    private static final int MAX_PACKET_NESTING_DEPTH = 16;

    private final ConsumerOptions options;
    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
    private final List<OnePassSignatureCheck> onePassSignatureChecks = new ArrayList<>();
    private final List<DetachedSignatureCheck> detachedSignatureChecks = new ArrayList<>();
    private final Map<Long, OnePassSignatureCheck> onePassSignaturesWithMissingCert = new HashMap<>();

    private static final PGPContentVerifierBuilderProvider verifierBuilderProvider =
            ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider();
    private IntegrityProtectedInputStream integrityProtectedEncryptedInputStream;


    public static DecryptionStream create(@Nonnull InputStream inputStream,
                                          @Nonnull ConsumerOptions options)
            throws PGPException, IOException {
        DecryptionStreamFactory factory = new DecryptionStreamFactory(options);
        OpenPgpInputStream openPgpIn = new OpenPgpInputStream(inputStream);
        return factory.parseOpenPGPDataAndCreateDecryptionStream(openPgpIn);
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
                SignatureValidationException ex = new SignatureValidationException(
                        "Missing verification certificate " + Long.toHexString(issuerKeyId));
                resultBuilder.addInvalidDetachedSignature(new SignatureVerification(signature, null), ex);
                continue;
            }
            PGPPublicKey signingKey = signingKeyRing.getPublicKey(issuerKeyId);
            SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(signingKeyRing, signingKey.getKeyID());
            try {
                signature.init(verifierBuilderProvider, signingKey);
                DetachedSignatureCheck detachedSignature =
                        new DetachedSignatureCheck(signature, signingKeyRing, signingKeyIdentifier);
                detachedSignatureChecks.add(detachedSignature);
            } catch (PGPException e) {
                SignatureValidationException ex = new SignatureValidationException(
                        "Cannot verify detached signature made by " + signingKeyIdentifier + ".", e);
                resultBuilder.addInvalidDetachedSignature(new SignatureVerification(signature, signingKeyIdentifier), ex);
            }
        }
    }

    private DecryptionStream parseOpenPGPDataAndCreateDecryptionStream(OpenPgpInputStream openPgpIn)
            throws IOException, PGPException {

        InputStream pgpInStream;
        InputStream outerDecodingStream;
        PGPObjectFactory objectFactory;

        // Non-OpenPGP data. We are probably verifying detached signatures
        if (openPgpIn.isNonOpenPgp() || options.isForceNonOpenPgpData()) {
            outerDecodingStream = openPgpIn;
            pgpInStream = wrapInVerifySignatureStream(outerDecodingStream, null);
            return new DecryptionStream(pgpInStream, resultBuilder, integrityProtectedEncryptedInputStream, null);
        }

        // Data appears to be OpenPGP message,
        //  or we handle it as such, since user provided a session-key for decryption
        if (openPgpIn.isLikelyOpenPgpMessage() ||
                (openPgpIn.isBinaryOpenPgp() && options.getSessionKey() != null)) {
            outerDecodingStream = openPgpIn;
            objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(outerDecodingStream);
            // Parse OpenPGP message
            pgpInStream = processPGPPackets(objectFactory, 1);
            return new DecryptionStream(pgpInStream,
                    resultBuilder, integrityProtectedEncryptedInputStream, null);
        }

        if (openPgpIn.isAsciiArmored()) {
            ArmoredInputStream armoredInputStream = ArmoredInputStreamFactory.get(openPgpIn);
            if (armoredInputStream.isClearText()) {
                resultBuilder.setCleartextSigned();
                return parseCleartextSignedMessage(armoredInputStream);
            } else {
                outerDecodingStream = armoredInputStream;
                objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(outerDecodingStream);
                // Parse OpenPGP message
                pgpInStream = processPGPPackets(objectFactory, 1);
                return new DecryptionStream(pgpInStream,
                        resultBuilder, integrityProtectedEncryptedInputStream,
                        outerDecodingStream);
            }
        }

        throw new PGPException("Not sure how to handle the input stream.");
    }

    private DecryptionStream parseCleartextSignedMessage(ArmoredInputStream armorIn)
            throws IOException, PGPException {
        resultBuilder.setCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED)
                .setFileEncoding(StreamEncoding.TEXT);

        MultiPassStrategy multiPassStrategy = options.getMultiPassStrategy();
        PGPSignatureList signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(armorIn, multiPassStrategy.getMessageOutputStream());

        for (PGPSignature signature : signatures) {
            options.addVerificationOfDetachedSignature(signature);
        }

        initializeDetachedSignatures(options.getDetachedSignatures());

        InputStream verifyIn = wrapInVerifySignatureStream(multiPassStrategy.getMessageInputStream(), null);
        return new DecryptionStream(verifyIn, resultBuilder, integrityProtectedEncryptedInputStream,
                null);
    }

    private InputStream wrapInVerifySignatureStream(InputStream bufferedIn, @Nullable PGPObjectFactory objectFactory) {
        return new SignatureInputStream.VerifySignatures(
                bufferedIn, objectFactory, onePassSignatureChecks,
                onePassSignaturesWithMissingCert, detachedSignatureChecks, options,
                resultBuilder);
    }

    private InputStream processPGPPackets(@Nonnull PGPObjectFactory objectFactory, int depth)
            throws IOException, PGPException {
        if (depth >= MAX_PACKET_NESTING_DEPTH) {
            throw new PGPException("Maximum depth of nested packages exceeded.");
        }
        Object nextPgpObject;
        try {
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
        } catch (FinalIOException e) {
            throw e;
        } catch (IOException e) {
            if (depth == 1 && e.getMessage().contains("invalid armor")) {
                throw e;
            }
            if (depth == 1 && e.getMessage().contains("unknown object in stream:")) {
                throw new MissingLiteralDataException("No Literal Data Packet found.");
            } else {
                throw new FinalIOException(e);
            }
        }

        throw new MissingLiteralDataException("No Literal Data Packet found");
    }

    private InputStream processPGPEncryptedDataList(PGPEncryptedDataList pgpEncryptedDataList, int depth)
            throws PGPException, IOException {
        LOGGER.debug("Depth {}: Encountered PGPEncryptedDataList", depth);

        SessionKey sessionKey = options.getSessionKey();
        if (sessionKey != null) {
            integrityProtectedEncryptedInputStream = decryptWithProvidedSessionKey(pgpEncryptedDataList, sessionKey);
            InputStream decodedDataStream = PGPUtil.getDecoderStream(integrityProtectedEncryptedInputStream);
            PGPObjectFactory factory = ImplementationFactory.getInstance().getPGPObjectFactory(decodedDataStream);
            return processPGPPackets(factory, ++depth);
        }

        InputStream decryptedDataStream = decryptSessionKey(pgpEncryptedDataList);
        InputStream decodedDataStream = PGPUtil.getDecoderStream(decryptedDataStream);
        PGPObjectFactory factory = ImplementationFactory.getInstance().getPGPObjectFactory(decodedDataStream);
        return processPGPPackets(factory, ++depth);
    }

    private IntegrityProtectedInputStream decryptWithProvidedSessionKey(
            PGPEncryptedDataList pgpEncryptedDataList,
            SessionKey sessionKey)
            throws PGPException {
        SessionKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                .getSessionKeyDataDecryptorFactory(sessionKey);
        InputStream decryptedDataStream = null;
        PGPEncryptedData encryptedData = null;
        for (PGPEncryptedData pgpEncryptedData : pgpEncryptedDataList) {
            encryptedData = pgpEncryptedData;
            if (!options.isIgnoreMDCErrors() && !encryptedData.isIntegrityProtected()) {
                throw new MessageNotIntegrityProtectedException();
            }

            if (encryptedData instanceof PGPPBEEncryptedData) {
                PGPPBEEncryptedData pbeEncrypted = (PGPPBEEncryptedData) encryptedData;
                decryptedDataStream = pbeEncrypted.getDataStream(decryptorFactory);
                break;
            } else if (encryptedData instanceof PGPPublicKeyEncryptedData) {
                PGPPublicKeyEncryptedData pkEncrypted = (PGPPublicKeyEncryptedData) encryptedData;
                decryptedDataStream = pkEncrypted.getDataStream(decryptorFactory);
                break;
            }
        }

        if (decryptedDataStream == null) {
            throw new PGPException("No valid PGP data encountered.");
        }

        resultBuilder.setSessionKey(sessionKey);
        throwIfAlgorithmIsRejected(sessionKey.getAlgorithm());
        integrityProtectedEncryptedInputStream =
                new IntegrityProtectedInputStream(decryptedDataStream, encryptedData, options);
        return integrityProtectedEncryptedInputStream;
    }

    private InputStream processPGPCompressedData(PGPCompressedData pgpCompressedData, int depth)
            throws PGPException, IOException {
        try {
            CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.requireFromId(pgpCompressedData.getAlgorithm());
            LOGGER.debug("Depth {}: Encountered PGPCompressedData: {}", depth, compressionAlgorithm);
            resultBuilder.setCompressionAlgorithm(compressionAlgorithm);
        } catch (NoSuchElementException e) {
            throw new PGPException("Unknown compression algorithm encountered.", e);
        }

        InputStream inflatedDataStream = pgpCompressedData.getDataStream();
        InputStream decodedDataStream = PGPUtil.getDecoderStream(inflatedDataStream);
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(decodedDataStream);

        return processPGPPackets(objectFactory, ++depth);
    }

    private InputStream processOnePassSignatureList(
            @Nonnull PGPObjectFactory objectFactory,
            PGPOnePassSignatureList onePassSignatures,
            int depth)
            throws PGPException, IOException {
        LOGGER.debug("Depth {}: Encountered PGPOnePassSignatureList of size {}", depth, onePassSignatures.size());
        initOnePassSignatures(onePassSignatures);
        return processPGPPackets(objectFactory, depth);
    }

    private InputStream processPGPLiteralData(
            @Nonnull PGPObjectFactory objectFactory,
            PGPLiteralData pgpLiteralData,
            int depth) {
        LOGGER.debug("Depth {}: Found PGPLiteralData", depth);
        InputStream literalDataInputStream = pgpLiteralData.getInputStream();

        resultBuilder.setFileName(pgpLiteralData.getFileName())
                .setModificationDate(pgpLiteralData.getModificationTime())
                .setFileEncoding(StreamEncoding.requireFromCode(pgpLiteralData.getFormat()));

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

                    PGPSessionKey pgpSessionKey = pbeEncryptedData.getSessionKey(passphraseDecryptor);
                    SessionKey sessionKey = new SessionKey(pgpSessionKey);
                    resultBuilder.setSessionKey(sessionKey);

                    throwIfAlgorithmIsRejected(sessionKey.getAlgorithm());

                    integrityProtectedEncryptedInputStream =
                            new IntegrityProtectedInputStream(decryptedDataStream, pbeEncryptedData, options);

                    return integrityProtectedEncryptedInputStream;
                } catch (PGPException e) {
                    LOGGER.debug("Probable passphrase mismatch, skip PBE encrypted data block", e);
                }
            }
        }

        // Try custom PublicKeyDataDecryptorFactories (e.g. hardware-backed).
        Map<Long, PublicKeyDataDecryptorFactory> customFactories = options.getCustomDecryptorFactories();
        for (PGPPublicKeyEncryptedData publicKeyEncryptedData : publicKeyProtected) {
            Long keyId = publicKeyEncryptedData.getKeyID();
            if (!customFactories.containsKey(keyId)) {
                continue;
            }

            PublicKeyDataDecryptorFactory decryptorFactory = customFactories.get(keyId);
            try {
                InputStream decryptedDataStream = publicKeyEncryptedData.getDataStream(decryptorFactory);
                PGPSessionKey pgpSessionKey = publicKeyEncryptedData.getSessionKey(decryptorFactory);
                SessionKey sessionKey = new SessionKey(pgpSessionKey);
                resultBuilder.setSessionKey(sessionKey);

                throwIfAlgorithmIsRejected(sessionKey.getAlgorithm());

                integrityProtectedEncryptedInputStream =
                        new IntegrityProtectedInputStream(decryptedDataStream, publicKeyEncryptedData, options);

                return integrityProtectedEncryptedInputStream;
            } catch (PGPException e) {
                LOGGER.debug("Decryption with custom PublicKeyDataDecryptorFactory failed", e);
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
                    List<PGPPublicKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);
                    for (PGPPublicKey pubkey : encryptionSubkeys) {
                        PGPSecretKey secretKey = secretKeys.getSecretKey(pubkey.getKeyID());
                        // Skip missing secret key
                        if (secretKey == null) {
                            continue;
                        }

                        privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData,
                                postponedDueToMissingPassphrase, true);
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

                // Make sure that the recipient key is encryption capable and non-expired
                KeyRingInfo info = new KeyRingInfo(secretKeys);
                List<PGPPublicKey> encryptionSubkeys = info.getEncryptionSubkeys(EncryptionPurpose.ANY);

                PGPSecretKey secretKey = null;
                for (PGPPublicKey pubkey : encryptionSubkeys) {
                    if (pubkey.getKeyID() == keyId) {
                        secretKey = secretKeys.getSecretKey(keyId);
                        break;
                    }
                }

                if (secretKey == null) {
                    LOGGER.debug("Key " + Long.toHexString(keyId) + " is not valid or not capable for decryption.");
                } else {
                    privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData,
                            postponedDueToMissingPassphrase, true);
                }
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

                    PGPPrivateKey privateKey = tryPublicKeyDecryption(secretKeys, secretKey, publicKeyEncryptedData,
                            postponedDueToMissingPassphrase, false);
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

        PGPSessionKey pgpSessionKey = encryptedSessionKey.getSessionKey(dataDecryptor);
        SessionKey sessionKey = new SessionKey(pgpSessionKey);
        resultBuilder.setSessionKey(sessionKey);

        SymmetricKeyAlgorithm symmetricKeyAlgorithm = sessionKey.getAlgorithm();
        if (symmetricKeyAlgorithm == SymmetricKeyAlgorithm.NULL) {
            LOGGER.debug("Message is unencrypted");
        } else {
            LOGGER.debug("Message is encrypted using {}", symmetricKeyAlgorithm);
        }
        throwIfAlgorithmIsRejected(symmetricKeyAlgorithm);

        integrityProtectedEncryptedInputStream = new IntegrityProtectedInputStream(
                encryptedSessionKey.getDataStream(dataDecryptor), encryptedSessionKey, options);
        return integrityProtectedEncryptedInputStream;
    }

    private void throwIfAlgorithmIsRejected(SymmetricKeyAlgorithm algorithm)
            throws UnacceptableAlgorithmException {
        if (!PGPainless.getPolicy().getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(algorithm)) {
            throw new UnacceptableAlgorithmException("Data is "
                    + (algorithm == SymmetricKeyAlgorithm.NULL ?
                    "unencrypted" :
                    "encrypted with symmetric algorithm " + algorithm) + " which is not acceptable as per PGPainless' policy.\n" +
                    "To mark this algorithm as acceptable, use PGPainless.getPolicy().setSymmetricKeyDecryptionAlgorithmPolicy().");
        }
    }

    private void initOnePassSignatures(@Nonnull PGPOnePassSignatureList onePassSignatureList)
            throws PGPException {
        Iterator<PGPOnePassSignature> iterator = onePassSignatureList.iterator();
        if (!iterator.hasNext()) {
            throw new PGPException("Verification failed - No OnePassSignatures found");
        }

        processOnePassSignatures(iterator);
    }

    private void processOnePassSignatures(Iterator<PGPOnePassSignature> signatures)
            throws PGPException {
        while (signatures.hasNext()) {
            PGPOnePassSignature signature = signatures.next();
            processOnePassSignature(signature);
        }
    }

    private void processOnePassSignature(PGPOnePassSignature signature)
            throws PGPException {
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
