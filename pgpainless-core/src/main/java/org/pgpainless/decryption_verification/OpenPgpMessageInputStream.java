// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.io.TeeInputStream;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.OpenPgpPacket;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.decryption_verification.syntax_check.InputSymbol;
import org.pgpainless.decryption_verification.syntax_check.PDA;
import org.pgpainless.decryption_verification.syntax_check.StackSymbol;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.MissingPassphraseException;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.KeyIdUtil;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.CertificateValidator;
import org.pgpainless.signature.consumer.OnePassSignatureCheck;
import org.pgpainless.signature.consumer.SignatureCheck;
import org.pgpainless.signature.consumer.SignatureValidator;
import org.pgpainless.util.ArmoredInputStreamFactory;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.SessionKey;
import org.pgpainless.util.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenPgpMessageInputStream extends DecryptionStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenPgpMessageInputStream.class);

    // Options to consume the data
    protected final ConsumerOptions options;

    private final Policy policy;
    // Pushdown Automaton to verify validity of OpenPGP packet sequence in an OpenPGP message
    protected final PDA syntaxVerifier = new PDA();
    // InputStream of OpenPGP packets
    protected TeeBCPGInputStream packetInputStream;
    // InputStream of a data packet containing nested data
    protected InputStream nestedInputStream;

    private boolean closed = false;

    private final Signatures signatures;
    private final MessageMetadata.Layer metadata;

    /**
     * Create an {@link OpenPgpMessageInputStream} suitable for decryption and verification of
     * OpenPGP messages and signatures.
     * This constructor will use the global PGPainless {@link Policy}.
     *
     * @param inputStream underlying input stream
     * @param options options for consuming the stream
     * @return input stream that consumes OpenPGP messages
     *
     * @throws IOException in case of an IO error
     * @throws PGPException in case of an OpenPGP error
     */
    public static OpenPgpMessageInputStream create(@Nonnull InputStream inputStream,
                                                   @Nonnull ConsumerOptions options)
            throws IOException, PGPException {
        return create(inputStream, options, PGPainless.getPolicy());
    }

    /**
     * Create an {@link OpenPgpMessageInputStream} suitable for decryption and verification of
     * OpenPGP messages and signatures.
     * This factory method takes a custom {@link Policy} instead of using the global policy object.
     *
     * @param inputStream underlying input stream containing the OpenPGP message
     * @param options options for consuming the message
     * @param policy policy for acceptable algorithms etc.
     * @return input stream that consumes OpenPGP messages
     *
     * @throws PGPException in case of an OpenPGP error
     * @throws IOException in case of an IO error
     */
    public static OpenPgpMessageInputStream create(@Nonnull InputStream inputStream,
                                                   @Nonnull ConsumerOptions options,
                                                   @Nonnull Policy policy)
            throws PGPException, IOException {
        return create(inputStream, options, new MessageMetadata.Message(), policy);
    }

    protected static OpenPgpMessageInputStream create(@Nonnull InputStream inputStream,
                                                      @Nonnull ConsumerOptions options,
                                                      @Nonnull MessageMetadata.Layer metadata,
                                                      @Nonnull Policy policy)
            throws IOException, PGPException {
        OpenPgpInputStream openPgpIn = new OpenPgpInputStream(inputStream);
        openPgpIn.reset();

        if (openPgpIn.isNonOpenPgp() || options.isForceNonOpenPgpData()) {
            return new OpenPgpMessageInputStream(Type.non_openpgp,
                    openPgpIn, options, metadata, policy);
        }

        if (openPgpIn.isBinaryOpenPgp()) {
            // Simply consume OpenPGP message
            return new OpenPgpMessageInputStream(Type.standard,
                    openPgpIn, options, metadata, policy);
        }

        if (openPgpIn.isAsciiArmored()) {
            ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(openPgpIn);
            if (armorIn.isClearText()) {
                ((MessageMetadata.Message) metadata).cleartextSigned = true;
                return new OpenPgpMessageInputStream(Type.cleartext_signed,
                        armorIn, options, metadata, policy);
            } else {
                // Simply consume dearmored OpenPGP message
                return new OpenPgpMessageInputStream(Type.standard,
                        armorIn, options, metadata, policy);
            }
        } else {
            throw new AssertionError("Cannot deduce type of data.");
        }
    }

    protected OpenPgpMessageInputStream(@Nonnull InputStream inputStream,
                                        @Nonnull ConsumerOptions options,
                                        @Nonnull MessageMetadata.Layer metadata,
                                        @Nonnull Policy policy)
            throws PGPException, IOException {
        super();

        this.policy = policy;
        this.options = options;
        this.metadata = metadata;
        this.signatures = new Signatures(options);

        // Add detached signatures only on the outermost OpenPgpMessageInputStream
        if (metadata instanceof MessageMetadata.Message) {
            this.signatures.addDetachedSignatures(options.getDetachedSignatures());
        }

        // tee out packet bytes for signature verification
        packetInputStream = new TeeBCPGInputStream(BCPGInputStream.wrap(inputStream), signatures);

        // *omnomnom*
        consumePackets();
    }

    enum Type {
        standard,
        cleartext_signed,
        non_openpgp
    }

    protected OpenPgpMessageInputStream(@Nonnull Type type,
                                        @Nonnull InputStream inputStream,
                                        @Nonnull ConsumerOptions options,
                                        @Nonnull MessageMetadata.Layer metadata,
                                        @Nonnull Policy policy) throws PGPException, IOException {
        super();
        this.policy = policy;
        this.options = options;
        this.metadata = metadata;
        this.signatures = new Signatures(options);

        if (metadata instanceof MessageMetadata.Message) {
            this.signatures.addDetachedSignatures(options.getDetachedSignatures());
        }

        switch (type) {

            // Binary OpenPGP Message
            case standard:
                // tee out packet bytes for signature verification
                packetInputStream = new TeeBCPGInputStream(BCPGInputStream.wrap(inputStream), this.signatures);

                // *omnomnom*
                consumePackets();
                break;

            // Cleartext Signature Framework (probably signed message)
            case cleartext_signed:
                MultiPassStrategy multiPassStrategy = options.getMultiPassStrategy();
                PGPSignatureList detachedSignatures = ClearsignedMessageUtil
                        .detachSignaturesFromInbandClearsignedMessage(
                                inputStream, multiPassStrategy.getMessageOutputStream());

                for (PGPSignature signature : detachedSignatures) {
                    signatures.addDetachedSignature(signature);
                }

                options.forceNonOpenPgpData();
                nestedInputStream = new TeeInputStream(multiPassStrategy.getMessageInputStream(), this.signatures);
                break;

            // Non-OpenPGP Data (e.g. detached signature verification)
            case non_openpgp:
                packetInputStream = null;
                nestedInputStream = new TeeInputStream(inputStream, this.signatures);
                break;
        }
    }

    /**
     * Consume OpenPGP packets from the current {@link BCPGInputStream}.
     * Once an OpenPGP packet with nested data (Literal Data, Compressed Data, Encrypted Data) is reached,
     * set <pre>nestedInputStream</pre> to the nested stream and breaks the loop.
     * The nested stream is either a simple {@link InputStream} (in case of Literal Data), or another
     * {@link OpenPgpMessageInputStream} in case of Compressed and Encrypted Data.
     * Once the nested data is processed, this method is called again to consume the remainder
     * of packets following the nested data packet.
     *
     * @throws IOException in case of an IO error
     * @throws PGPException in case of an OpenPGP error
     * @throws MissingDecryptionMethodException if there is an encrypted data packet which cannot be decrypted
     * due to missing decryption methods (no key, no password, no sessionkey)
     * @throws MalformedOpenPgpMessageException if the message is made of an invalid packet sequence which
     * does not follow the packet syntax of RFC4880.
     */
    private void consumePackets()
            throws IOException, PGPException {
        OpenPgpPacket nextPacket;
        if (packetInputStream == null) {
            return;
        }

        loop: // we break this when we enter nested packets and later resume
        while ((nextPacket = packetInputStream.nextPacketTag()) != null) {
            signatures.nextPacket(nextPacket);
            switch (nextPacket) {

                // Literal Data - the literal data content is the new input stream
                case LIT:
                    processLiteralData();
                    break loop;

                // Compressed Data - the content contains another OpenPGP message
                case COMP:
                    processCompressedData();
                    break loop;

                // One Pass Signature
                case OPS:
                    processOnePassSignature();
                    break;

                // Signature - either prepended to the message, or corresponding to a One Pass Signature
                case SIG:
                    processSignature();
                    break;

                // Encrypted Data (ESKs and SED/SEIPD are parsed the same by BC)
                case PKESK:
                case SKESK:
                case SED:
                case SEIPD:
                    if (processEncryptedData()) {
                        // Successfully decrypted, enter nested content
                        break loop;
                    }

                    throw new MissingDecryptionMethodException("No working decryption method found.");

                    // Marker Packets need to be skipped and ignored
                case MARKER:
                    LOGGER.debug("Skipping Marker Packet");
                    packetInputStream.readMarker();
                    break;

                // Key Packets are illegal in this context
                case SK:
                case PK:
                case SSK:
                case PSK:
                case TRUST:
                case UID:
                case UATTR:
                    throw new MalformedOpenPgpMessageException("Illegal Packet in Stream: " + nextPacket);

                    // MDC packet is usually processed by PGPEncryptedDataList, so it is very likely we encounter this
                    //  packet out of order
                case MDC:
                    throw new MalformedOpenPgpMessageException("Unexpected Packet in Stream: " + nextPacket);

                    // Experimental Packets are not supported
                case EXP_1:
                case EXP_2:
                case EXP_3:
                case EXP_4:
                    throw new MalformedOpenPgpMessageException("Unsupported Packet in Stream: " + nextPacket);
            }
        }
    }

    private void processLiteralData() throws IOException {
        LOGGER.debug("Literal Data Packet at depth " + metadata.depth + " encountered");
        syntaxVerifier.next(InputSymbol.LiteralData);
        PGPLiteralData literalData = packetInputStream.readLiteralData();
        // Extract Metadata
        this.metadata.setChild(new MessageMetadata.LiteralData(
                literalData.getFileName(),
                literalData.getModificationTime(),
                StreamEncoding.requireFromCode(literalData.getFormat())));

        nestedInputStream = literalData.getDataStream();
    }

    private void processCompressedData() throws IOException, PGPException {
        syntaxVerifier.next(InputSymbol.CompressedData);
        signatures.enterNesting();
        PGPCompressedData compressedData = packetInputStream.readCompressedData();
        // Extract Metadata
        MessageMetadata.CompressedData compressionLayer = new MessageMetadata.CompressedData(
                CompressionAlgorithm.requireFromId(compressedData.getAlgorithm()),
                metadata.depth + 1);

        LOGGER.debug("Compressed Data Packet (" + compressionLayer.algorithm + ") at depth " + metadata.depth + " encountered");
        InputStream decompressed = compressedData.getDataStream();
        nestedInputStream = new OpenPgpMessageInputStream(decompressed, options, compressionLayer, policy);
    }

    private void processOnePassSignature() throws PGPException, IOException {
        syntaxVerifier.next(InputSymbol.OnePassSignature);
        PGPOnePassSignature onePassSignature = packetInputStream.readOnePassSignature();
        LOGGER.debug("One-Pass-Signature Packet by key " + KeyIdUtil.formatKeyId(onePassSignature.getKeyID()) +
                " at depth " + metadata.depth + " encountered");
        signatures.addOnePassSignature(onePassSignature);
    }

    private void processSignature() throws PGPException, IOException {
        // true if Signature corresponds to OnePassSignature
        boolean isSigForOPS = syntaxVerifier.peekStack() == StackSymbol.ops;
        syntaxVerifier.next(InputSymbol.Signature);
        PGPSignature signature;
        try {
            signature = packetInputStream.readSignature();
        } catch (UnsupportedPacketVersionException e) {
            LOGGER.debug("Unsupported Signature at depth " + metadata.depth + " encountered.", e);
            return;
        }

        long keyId = SignatureUtils.determineIssuerKeyId(signature);
        if (isSigForOPS) {
            LOGGER.debug("Signature Packet corresponding to One-Pass-Signature by key " +
                    KeyIdUtil.formatKeyId(keyId) +
                    " at depth " + metadata.depth + " encountered");
            signatures.leaveNesting(); // TODO: Only leave nesting if all OPSs of the nesting layer are dealt with
            signatures.addCorrespondingOnePassSignature(signature, metadata, policy);
        } else {
            LOGGER.debug("Prepended Signature Packet by key " +
                    KeyIdUtil.formatKeyId(keyId) +
                    " at depth " + metadata.depth + " encountered");
            signatures.addPrependedSignature(signature);
        }
    }

    private boolean processEncryptedData() throws IOException, PGPException {
        LOGGER.debug("Symmetrically Encrypted Data Packet at depth " + metadata.depth + " encountered");
        syntaxVerifier.next(InputSymbol.EncryptedData);
        PGPEncryptedDataList encDataList = packetInputStream.readEncryptedDataList();

        if (!encDataList.isIntegrityProtected()) {
            LOGGER.warn("Symmetrically Encrypted Data Packet is not integrity-protected.");
            if (!options.isIgnoreMDCErrors()) {
                throw new MessageNotIntegrityProtectedException();
            }
        }

        SortedESKs esks = new SortedESKs(encDataList);
        LOGGER.debug("Symmetrically Encrypted Integrity-Protected Data has " +
                esks.skesks.size() + " SKESK(s) and " +
                (esks.pkesks.size() + esks.anonPkesks.size()) + " PKESK(s) from which " +
                esks.anonPkesks.size() + " PKESK(s) have an anonymous recipient");

        // Try custom decryptor factories
        for (SubkeyIdentifier subkeyIdentifier : options.getCustomDecryptorFactories().keySet()) {
            LOGGER.debug("Attempt decryption with custom decryptor factory with key " + subkeyIdentifier);
            PublicKeyDataDecryptorFactory decryptorFactory = options.getCustomDecryptorFactories().get(subkeyIdentifier);
            for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
                // find matching PKESK
                if (pkesk.getKeyID() != subkeyIdentifier.getSubkeyId()) {
                    continue;
                }

                // attempt decryption
                if (decryptPKESKAndStream(esks, subkeyIdentifier, decryptorFactory, pkesk)) {
                    return true;
                }
            }
        }

        // Try provided session key
        if (options.getSessionKey() != null) {
            LOGGER.debug("Attempt decryption with provided session key");
            SessionKey sessionKey = options.getSessionKey();
            throwIfUnacceptable(sessionKey.getAlgorithm());

            SessionKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                    .getSessionKeyDataDecryptorFactory(sessionKey);
            MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                    sessionKey.getAlgorithm(), metadata.depth + 1);

            PGPSessionKeyEncryptedData sessionKeyEncryptedData = encDataList.extractSessionKeyEncryptedData();
            try {
                InputStream decrypted = sessionKeyEncryptedData.getDataStream(decryptorFactory);
                encryptedData.sessionKey = sessionKey;
                IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, sessionKeyEncryptedData, options);
                nestedInputStream = new OpenPgpMessageInputStream(integrityProtected, options, encryptedData, policy);
                LOGGER.debug("Successfully decrypted data with provided session key");
                return true;
            } catch (PGPException e) {
                // Session key mismatch?
                LOGGER.debug("Decryption using provided session key failed. Mismatched session key and message?", e);
            }
        }

        // Try passwords
        for (Passphrase passphrase : options.getDecryptionPassphrases()) {
            for (PGPPBEEncryptedData skesk : esks.skesks) {
                LOGGER.debug("Attempt decryption with provided passphrase");
                SymmetricKeyAlgorithm encapsulationAlgorithm = SymmetricKeyAlgorithm.requireFromId(skesk.getAlgorithm());
                try {
                    throwIfUnacceptable(encapsulationAlgorithm);
                } catch (UnacceptableAlgorithmException e) {
                    LOGGER.debug("Skipping SKESK with unacceptable encapsulation algorithm", e);
                    continue;
                }

                PBEDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                        .getPBEDataDecryptorFactory(passphrase);
                if (decryptSKESKAndStream(esks, skesk, decryptorFactory)) {
                    return true;
                }
            }
        }

        List<Tuple<PGPSecretKey, PGPPublicKeyEncryptedData>> postponedDueToMissingPassphrase = new ArrayList<>();

        // Try (known) secret keys
        for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
            long keyId = pkesk.getKeyID();
            LOGGER.debug("Encountered PKESK for recipient " + KeyIdUtil.formatKeyId(keyId));
            PGPSecretKeyRing decryptionKeys = getDecryptionKey(keyId);
            if (decryptionKeys == null) {
                LOGGER.debug("Skipping PKESK because no matching key " + KeyIdUtil.formatKeyId(keyId) + " was provided");
                continue;
            }
            PGPSecretKey secretKey = decryptionKeys.getSecretKey(keyId);
            SubkeyIdentifier decryptionKeyId = new SubkeyIdentifier(decryptionKeys, secretKey.getKeyID());
            if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                continue;
            }
            LOGGER.debug("Attempt decryption using secret key " + decryptionKeyId);

            SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeys);
            // Postpone keys with missing passphrase
            if (!protector.hasPassphraseFor(keyId)) {
                LOGGER.debug("Missing passphrase for key " + decryptionKeyId + ". Postponing decryption until all other keys were tried");
                postponedDueToMissingPassphrase.add(new Tuple<>(secretKey, pkesk));
                continue;
            }

            PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, protector);
            if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                return true;
            }
        }

        // try anonymous secret keys
        for (PGPPublicKeyEncryptedData pkesk : esks.anonPkesks) {
            for (Tuple<PGPSecretKeyRing, PGPSecretKey> decryptionKeyCandidate : findPotentialDecryptionKeys(pkesk)) {
                PGPSecretKeyRing decryptionKeys = decryptionKeyCandidate.getA();
                PGPSecretKey secretKey = decryptionKeyCandidate.getB();
                SubkeyIdentifier decryptionKeyId = new SubkeyIdentifier(decryptionKeys, secretKey.getKeyID());
                if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                    continue;
                }
                LOGGER.debug("Attempt decryption of anonymous PKESK with key " + decryptionKeyId);
                SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeyCandidate.getA());
                if (!protector.hasPassphraseFor(secretKey.getKeyID())) {
                    LOGGER.debug("Missing passphrase for key " + decryptionKeyId + ". Postponing decryption until all other keys were tried.");
                    postponedDueToMissingPassphrase.add(new Tuple<>(secretKey, pkesk));
                    continue;
                }

                PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, protector);
                if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                    return true;
                }
            }
        }

        if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.THROW_EXCEPTION) {
            // Non-interactive mode: Throw an exception with all locked decryption keys
            Set<SubkeyIdentifier> keyIds = new HashSet<>();
            for (Tuple<PGPSecretKey, PGPPublicKeyEncryptedData> k : postponedDueToMissingPassphrase) {
                PGPSecretKey key = k.getA();
                PGPSecretKeyRing keys = getDecryptionKey(key.getKeyID());
                keyIds.add(new SubkeyIdentifier(keys, key.getKeyID()));
            }
            if (!keyIds.isEmpty()) {
                throw new MissingPassphraseException(keyIds);
            }
        } else if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.INTERACTIVE) {
            for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
                // Interactive mode: Fire protector callbacks to get passphrases interactively
                for (Tuple<PGPSecretKey, PGPPublicKeyEncryptedData> missingPassphrases : postponedDueToMissingPassphrase) {
                    PGPSecretKey secretKey = missingPassphrases.getA();
                    long keyId = secretKey.getKeyID();
                    PGPSecretKeyRing decryptionKey = getDecryptionKey(keyId);
                    SubkeyIdentifier decryptionKeyId = new SubkeyIdentifier(decryptionKey, keyId);
                    if (hasUnsupportedS2KSpecifier(secretKey, decryptionKeyId)) {
                        continue;
                    }

                    LOGGER.debug("Attempt decryption with key " + decryptionKeyId + " while interactively requesting its passphrase");
                    SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKey);
                    PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, protector);
                    if (decryptWithPrivateKey(esks, privateKey, decryptionKeyId, pkesk)) {
                        return true;
                    }
                }
            }
        } else {
            throw new IllegalStateException("Invalid PostponedKeysStrategy set in consumer options.");
        }

        // we did not yet succeed in decrypting any session key :/

        LOGGER.debug("Failed to decrypt encrypted data packet");
        return false;
    }

    private boolean decryptWithPrivateKey(SortedESKs esks,
                                          PGPPrivateKey privateKey,
                                          SubkeyIdentifier decryptionKeyId,
                                          PGPPublicKeyEncryptedData pkesk)
            throws PGPException, IOException {
        PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                .getPublicKeyDataDecryptorFactory(privateKey);
        return decryptPKESKAndStream(esks, decryptionKeyId, decryptorFactory, pkesk);
    }

    private static boolean hasUnsupportedS2KSpecifier(PGPSecretKey secretKey, SubkeyIdentifier decryptionKeyId) {
        S2K s2K = secretKey.getS2K();
        if (s2K != null) {
            int s2kType = s2K.getType();
            if (s2kType >= 100 && s2kType <= 110) {
                LOGGER.debug("Skipping PKESK because key " + decryptionKeyId + " has unsupported private S2K specifier " + s2kType);
                return true;
            }
        }
        return false;
    }

    private boolean decryptSKESKAndStream(SortedESKs esks,
                                          PGPPBEEncryptedData symEsk,
                                          PBEDataDecryptorFactory decryptorFactory)
            throws IOException, UnacceptableAlgorithmException {
        try {
            InputStream decrypted = symEsk.getDataStream(decryptorFactory);
            SessionKey sessionKey = new SessionKey(symEsk.getSessionKey(decryptorFactory));
            throwIfUnacceptable(sessionKey.getAlgorithm());
            MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                    sessionKey.getAlgorithm(), metadata.depth + 1);
            encryptedData.sessionKey = sessionKey;
            encryptedData.recipients = new ArrayList<>();
            for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
                encryptedData.recipients.add(pkesk.getKeyID());
            }
            LOGGER.debug("Successfully decrypted data with passphrase");
            IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, symEsk, options);
            nestedInputStream = new OpenPgpMessageInputStream(integrityProtected, options, encryptedData, policy);
            return true;
        } catch (UnacceptableAlgorithmException e) {
            throw e;
        } catch (PGPException e) {
            LOGGER.debug("Decryption of encrypted data packet using password failed. Password mismatch?", e);
        }
        return false;
    }

    private boolean decryptPKESKAndStream(SortedESKs esks,
                                          SubkeyIdentifier decryptionKeyId,
                                          PublicKeyDataDecryptorFactory decryptorFactory,
                                          PGPPublicKeyEncryptedData asymEsk)
            throws IOException, UnacceptableAlgorithmException {
        try {
            InputStream decrypted = asymEsk.getDataStream(decryptorFactory);
            SessionKey sessionKey = new SessionKey(asymEsk.getSessionKey(decryptorFactory));
            throwIfUnacceptable(sessionKey.getAlgorithm());

            MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                    SymmetricKeyAlgorithm.requireFromId(asymEsk.getSymmetricAlgorithm(decryptorFactory)),
                    metadata.depth + 1);
            encryptedData.decryptionKey = decryptionKeyId;
            encryptedData.sessionKey = sessionKey;
            encryptedData.recipients = new ArrayList<>();
            for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
                encryptedData.recipients.add(pkesk.getKeyID());
            }

            LOGGER.debug("Successfully decrypted data with key " + decryptionKeyId);
            IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, asymEsk, options);
            nestedInputStream = new OpenPgpMessageInputStream(integrityProtected, options, encryptedData, policy);
            return true;
        } catch (UnacceptableAlgorithmException e) {
            throw e;
        } catch (PGPException e) {
            LOGGER.debug("Decryption of encrypted data packet using secret key failed.", e);
        }
        return false;
    }

    private void throwIfUnacceptable(SymmetricKeyAlgorithm algorithm)
            throws UnacceptableAlgorithmException {
        if (!policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(algorithm)) {
            throw new UnacceptableAlgorithmException("Symmetric-Key algorithm " + algorithm + " is not acceptable for message decryption.");
        }
    }

    private List<Tuple<PGPSecretKeyRing, PGPSecretKey>> findPotentialDecryptionKeys(PGPPublicKeyEncryptedData pkesk) {
        int algorithm = pkesk.getAlgorithm();
        List<Tuple<PGPSecretKeyRing, PGPSecretKey>> decryptionKeyCandidates = new ArrayList<>();

        for (PGPSecretKeyRing secretKeys : options.getDecryptionKeys()) {
            KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
            for (PGPPublicKey publicKey : info.getDecryptionSubkeys()) {
                if (publicKey.getAlgorithm() == algorithm && info.isSecretKeyAvailable(publicKey.getKeyID())) {
                    PGPSecretKey candidate = secretKeys.getSecretKey(publicKey.getKeyID());
                    decryptionKeyCandidates.add(new Tuple<>(secretKeys, candidate));
                }
            }
        }
        return decryptionKeyCandidates;
    }

    private PGPSecretKeyRing getDecryptionKey(long keyID) {
        for (PGPSecretKeyRing secretKeys : options.getDecryptionKeys()) {
            PGPSecretKey decryptionKey = secretKeys.getSecretKey(keyID);
            if (decryptionKey == null) {
                continue;
            }

            KeyRingInfo info = new KeyRingInfo(secretKeys, policy, new Date());
            List<PGPPublicKey> encryptionKeys = info.getDecryptionSubkeys();
            for (PGPPublicKey key : encryptionKeys) {
                if (key.getKeyID() == keyID) {
                    return secretKeys;
                }
            }

            LOGGER.debug("Subkey " + Long.toHexString(keyID) + " cannot be used for decryption.");
        }
        return null;
    }

    @Override
    public int read() throws IOException {
        if (nestedInputStream == null) {
            if (packetInputStream != null) {
                syntaxVerifier.assertValid();
            }
            return -1;
        }

        int r;
        try {
            r = nestedInputStream.read();
        } catch (IOException e) {
            r = -1;
        }
        boolean eos = r == -1;
        if (!eos) {
            byte b = (byte) r;
            signatures.updateLiteral(b);
        } else {
            nestedInputStream.close();
            collectMetadata();
            nestedInputStream = null;

            if (packetInputStream != null) {
                try {
                    consumePackets();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
            signatures.finish(metadata, policy);
        }
        return r;
    }

    @Override
    public int read(@Nonnull byte[] b, int off, int len)
            throws IOException {
        if (nestedInputStream == null) {
            if (packetInputStream != null) {
                syntaxVerifier.next(InputSymbol.EndOfSequence);
                syntaxVerifier.assertValid();
            }
            return -1;
        }

        int r = nestedInputStream.read(b, off, len);
        if (r != -1) {
            signatures.updateLiteral(b, off, r);
        } else  {
            nestedInputStream.close();
            collectMetadata();
            nestedInputStream = null;

            if (packetInputStream != null) {
                try {
                    consumePackets();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
            signatures.finish(metadata, policy);
        }
        return r;
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (closed) {
            if (packetInputStream != null) {
                syntaxVerifier.next(InputSymbol.EndOfSequence);
                syntaxVerifier.assertValid();
            }
            return;
        }

        if (nestedInputStream != null) {
            nestedInputStream.close();
            collectMetadata();
            nestedInputStream = null;
        }

        try {
            consumePackets();
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

        if (packetInputStream != null) {
            syntaxVerifier.next(InputSymbol.EndOfSequence);
            syntaxVerifier.assertValid();
            packetInputStream.close();
        }
        closed = true;
    }

    private void collectMetadata() {
        if (nestedInputStream instanceof OpenPgpMessageInputStream) {
            OpenPgpMessageInputStream child = (OpenPgpMessageInputStream) nestedInputStream;
            this.metadata.setChild((MessageMetadata.Nested) child.metadata);
        }
    }

    public MessageMetadata getMetadata() {
        if (!closed) {
            throw new IllegalStateException("Stream must be closed before access to metadata can be granted.");
        }

        return new MessageMetadata((MessageMetadata.Message) metadata);
    }

    private static class SortedESKs {

        private final List<PGPPBEEncryptedData> skesks = new ArrayList<>();
        private final List<PGPPublicKeyEncryptedData> pkesks = new ArrayList<>();
        private final List<PGPPublicKeyEncryptedData> anonPkesks = new ArrayList<>();

        SortedESKs(PGPEncryptedDataList esks) {
            for (PGPEncryptedData esk : esks) {
                if (esk instanceof PGPPBEEncryptedData) {
                    skesks.add((PGPPBEEncryptedData) esk);
                }
                else if (esk instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) esk;
                    if (pkesk.getKeyID() != 0) {
                        pkesks.add(pkesk);
                    } else {
                        anonPkesks.add(pkesk);
                    }
                } else {
                    throw new IllegalArgumentException("Unknown ESK class type.");
                }
            }
        }

        public List<PGPEncryptedData> all() {
            List<PGPEncryptedData> esks = new ArrayList<>();
            esks.addAll(skesks);
            esks.addAll(pkesks);
            esks.addAll(anonPkesks);
            return esks;
        }
    }

    // In 'OPS LIT("Foo") SIG', OPS is only updated with "Foo"
    // In 'OPS[1] OPS LIT("Foo") SIG SIG', OPS[1] (nested) is updated with OPS LIT("Foo") SIG.
    // Therefore, we need to handle the innermost signature layer differently when updating with Literal data.
    // Furthermore, For 'OPS COMP(LIT("Foo")) SIG', the signature is updated with "Foo". CHAOS!!!
    private static final class Signatures extends OutputStream {
        final ConsumerOptions options;
        final List<SignatureCheck> detachedSignatures;
        final List<SignatureCheck> prependedSignatures;
        final List<OnePassSignatureCheck> onePassSignatures;
        final Stack<List<OnePassSignatureCheck>> opsUpdateStack;
        List<OnePassSignatureCheck> literalOPS = new ArrayList<>();
        final List<PGPSignature> correspondingSignatures;
        final List<SignatureVerification.Failure> prependedSignaturesWithMissingCert = new ArrayList<>();
        final List<SignatureVerification.Failure> inbandSignaturesWithMissingCert = new ArrayList<>();
        final List<SignatureVerification.Failure> detachedSignaturesWithMissingCert = new ArrayList<>();
        boolean isLiteral = true;

        private Signatures(ConsumerOptions options) {
            this.options = options;
            this.detachedSignatures = new ArrayList<>();
            this.prependedSignatures = new ArrayList<>();
            this.onePassSignatures = new ArrayList<>();
            this.opsUpdateStack = new Stack<>();
            this.correspondingSignatures = new ArrayList<>();
        }

        void addDetachedSignatures(Collection<PGPSignature> signatures) {
            for (PGPSignature signature : signatures) {
                addDetachedSignature(signature);
            }
        }

        void addDetachedSignature(PGPSignature signature) {
            SignatureCheck check = initializeSignature(signature);
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            if (check != null) {
                detachedSignatures.add(check);
            } else {
                LOGGER.debug("No suitable certificate for verification of signature by key " + KeyIdUtil.formatKeyId(keyId) + " found.");
                this.detachedSignaturesWithMissingCert.add(new SignatureVerification.Failure(
                        new SignatureVerification(signature, null),
                        new SignatureValidationException("Missing verification key")
                ));
            }
        }

        void addPrependedSignature(PGPSignature signature) {
            SignatureCheck check = initializeSignature(signature);
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            if (check != null) {
                this.prependedSignatures.add(check);
            } else {
                LOGGER.debug("No suitable certificate for verification of signature by key " + KeyIdUtil.formatKeyId(keyId) + " found.");
                this.prependedSignaturesWithMissingCert.add(new SignatureVerification.Failure(
                        new SignatureVerification(signature, null),
                        new SignatureValidationException("Missing verification key")
                ));
            }
        }

        SignatureCheck initializeSignature(PGPSignature signature) {
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing certificate = findCertificate(keyId);
            if (certificate == null) {
                return null;
            }

            SubkeyIdentifier verifierKey = new SubkeyIdentifier(certificate, keyId);
            initialize(signature, certificate, keyId);
            return new SignatureCheck(signature, certificate, verifierKey);
        }

        void addOnePassSignature(PGPOnePassSignature signature) {
            PGPPublicKeyRing certificate = findCertificate(signature.getKeyID());

            if (certificate != null) {
                OnePassSignatureCheck ops = new OnePassSignatureCheck(signature, certificate);
                initialize(signature, certificate);
                onePassSignatures.add(ops);

                literalOPS.add(ops);
            }
            if (signature.isContaining()) {
                enterNesting();
            }
        }

        void addCorrespondingOnePassSignature(PGPSignature signature, MessageMetadata.Layer layer, Policy policy) {
            boolean found = false;
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            for (int i = onePassSignatures.size() - 1; i >= 0; i--) {
                OnePassSignatureCheck onePassSignature = onePassSignatures.get(i);
                if (onePassSignature.getOnePassSignature().getKeyID() != keyId) {
                    continue;
                }
                found = true;

                if (onePassSignature.getSignature() != null) {
                    continue;
                }

                onePassSignature.setSignature(signature);
                SignatureVerification verification = new SignatureVerification(signature,
                        new SubkeyIdentifier(onePassSignature.getVerificationKeys(), onePassSignature.getOnePassSignature().getKeyID()));

                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(signature);
                    CertificateValidator.validateCertificateAndVerifyOnePassSignature(onePassSignature, policy);
                    LOGGER.debug("Acceptable signature by key " + verification.getSigningKey());
                    layer.addVerifiedOnePassSignature(verification);
                } catch (SignatureValidationException e) {
                    LOGGER.debug("Rejected signature by key " + verification.getSigningKey(), e);
                    layer.addRejectedOnePassSignature(new SignatureVerification.Failure(verification, e));
                }
                break;
            }

            if (!found) {
                LOGGER.debug("No suitable certificate for verification of signature by key " + KeyIdUtil.formatKeyId(keyId) + " found.");
                inbandSignaturesWithMissingCert.add(new SignatureVerification.Failure(
                        new SignatureVerification(signature, null),
                        new SignatureValidationException("Missing verification key")));
            }
        }

        void enterNesting() {
            opsUpdateStack.push(literalOPS);
            literalOPS = new ArrayList<>();
        }

        void leaveNesting() {
            if (opsUpdateStack.isEmpty()) {
                return;
            }
            opsUpdateStack.pop();
        }

        private static void initialize(@Nonnull PGPSignature signature, @Nonnull PGPPublicKeyRing certificate, long keyId) {
            PGPContentVerifierBuilderProvider verifierProvider = ImplementationFactory.getInstance()
                    .getPGPContentVerifierBuilderProvider();
            try {
                signature.init(verifierProvider, certificate.getPublicKey(keyId));
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }

        private static void initialize(@Nonnull PGPOnePassSignature ops, @Nonnull PGPPublicKeyRing certificate) {
            PGPContentVerifierBuilderProvider verifierProvider = ImplementationFactory.getInstance()
                    .getPGPContentVerifierBuilderProvider();
            try {
                ops.init(verifierProvider, certificate.getPublicKey(ops.getKeyID()));
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }

        private PGPPublicKeyRing findCertificate(long keyId) {
            PGPPublicKeyRing cert = options.getCertificateSource().getCertificate(keyId);
            if (cert != null) {
                return cert;
            }

            if (options.getMissingCertificateCallback() != null) {
                return options.getMissingCertificateCallback().onMissingPublicKeyEncountered(keyId);
            }
            return null; // TODO: Missing cert for sig
        }

        public void updateLiteral(byte b) {
            for (OnePassSignatureCheck ops : literalOPS) {
                ops.getOnePassSignature().update(b);
            }

            for (SignatureCheck detached : detachedSignatures) {
                detached.getSignature().update(b);
            }

            for (SignatureCheck prepended : prependedSignatures) {
                prepended.getSignature().update(b);
            }
        }

        public void updateLiteral(byte[] b, int off, int len) {
            for (OnePassSignatureCheck ops : literalOPS) {
                ops.getOnePassSignature().update(b, off, len);
            }

            for (SignatureCheck detached : detachedSignatures) {
                detached.getSignature().update(b, off, len);
            }

            for (SignatureCheck prepended : prependedSignatures) {
                prepended.getSignature().update(b, off, len);
            }
        }

        public void updatePacket(byte b) {
            for (int i = opsUpdateStack.size() - 1; i >= 0; i--) {
                List<OnePassSignatureCheck> nestedOPSs = opsUpdateStack.get(i);
                for (OnePassSignatureCheck ops : nestedOPSs) {
                    ops.getOnePassSignature().update(b);
                }
            }
        }

        public void updatePacket(byte[] buf, int off, int len) {
            for (int i = opsUpdateStack.size() - 1; i >= 0; i--) {
                List<OnePassSignatureCheck> nestedOPSs = opsUpdateStack.get(i);
                for (OnePassSignatureCheck ops : nestedOPSs) {
                    ops.getOnePassSignature().update(buf, off, len);
                }
            }
        }

        public void finish(MessageMetadata.Layer layer, Policy policy) {
            for (SignatureCheck detached : detachedSignatures) {
                SignatureVerification verification = new SignatureVerification(detached.getSignature(), detached.getSigningKeyIdentifier());
                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(detached.getSignature());
                    CertificateValidator.validateCertificateAndVerifyInitializedSignature(
                            detached.getSignature(), KeyRingUtils.publicKeys(detached.getSigningKeyRing()), policy);
                    LOGGER.debug("Acceptable signature by key " + verification.getSigningKey());
                    layer.addVerifiedDetachedSignature(verification);
                } catch (SignatureValidationException e) {
                    LOGGER.debug("Rejected signature by key " + verification.getSigningKey(), e);
                    layer.addRejectedDetachedSignature(new SignatureVerification.Failure(verification, e));
                }
            }

            for (SignatureCheck prepended : prependedSignatures) {
                SignatureVerification verification = new SignatureVerification(prepended.getSignature(), prepended.getSigningKeyIdentifier());
                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(prepended.getSignature());
                    CertificateValidator.validateCertificateAndVerifyInitializedSignature(
                            prepended.getSignature(), KeyRingUtils.publicKeys(prepended.getSigningKeyRing()), policy);
                    LOGGER.debug("Acceptable signature by key " + verification.getSigningKey());
                    layer.addVerifiedPrependedSignature(verification);
                } catch (SignatureValidationException e) {
                    LOGGER.debug("Rejected signature by key " + verification.getSigningKey(), e);
                    layer.addRejectedPrependedSignature(new SignatureVerification.Failure(verification, e));
                }
            }

            for (SignatureVerification.Failure rejected : inbandSignaturesWithMissingCert) {
                layer.addRejectedOnePassSignature(rejected);
            }

            for (SignatureVerification.Failure rejected : prependedSignaturesWithMissingCert) {
                layer.addRejectedPrependedSignature(rejected);
            }

            for (SignatureVerification.Failure rejected : detachedSignaturesWithMissingCert) {
                layer.addRejectedDetachedSignature(rejected);
            }
        }

        @Override
        public void write(int b) {
            updatePacket((byte) b);
        }

        @Override
        public void write(@Nonnull byte[] b, int off, int len) {
            updatePacket(b, off, len);
        }

        public void nextPacket(OpenPgpPacket nextPacket) {
            if (nextPacket == OpenPgpPacket.LIT) {
                isLiteral = true;
                if (literalOPS.isEmpty() && !opsUpdateStack.isEmpty()) {
                    literalOPS = opsUpdateStack.pop();
                }
            } else {
                isLiteral = false;
            }
        }

    }
}
