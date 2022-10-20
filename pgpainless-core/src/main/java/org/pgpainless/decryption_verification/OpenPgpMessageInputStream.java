// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
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
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.OpenPgpPacket;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.automaton.InputAlphabet;
import org.pgpainless.decryption_verification.automaton.PDA;
import org.pgpainless.decryption_verification.automaton.StackAlphabet;
import org.pgpainless.decryption_verification.cleartext_signatures.ClearsignedMessageUtil;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
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
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.OnePassSignatureCheck;
import org.pgpainless.signature.consumer.SignatureCheck;
import org.pgpainless.signature.consumer.SignatureValidator;
import org.pgpainless.signature.consumer.SignatureVerifier;
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
    // Pushdown Automaton to verify validity of OpenPGP packet sequence in an OpenPGP message
    protected final PDA automaton = new PDA();
    // InputStream of OpenPGP packets
    protected TeeBCPGInputStream packetInputStream;
    // InputStream of a nested data packet
    protected InputStream nestedInputStream;

    private boolean closed = false;

    private final Signatures signatures;
    private final MessageMetadata.Layer metadata;
    private final Policy policy;

    public OpenPgpMessageInputStream(@Nonnull InputStream inputStream,
                                     @Nonnull ConsumerOptions options)
            throws IOException, PGPException {
        this(inputStream, options, PGPainless.getPolicy());
    }

    public OpenPgpMessageInputStream(@Nonnull InputStream inputStream,
                                     @Nonnull ConsumerOptions options,
                                     @Nonnull Policy policy)
            throws PGPException, IOException {
        this(
                prepareInputStream(inputStream, options, policy),
                options, new MessageMetadata.Message(), policy);
    }

    protected OpenPgpMessageInputStream(@Nonnull InputStream inputStream,
                                        @Nonnull ConsumerOptions options,
                                        @Nonnull MessageMetadata.Layer metadata,
                                        @Nonnull Policy policy)
            throws PGPException, IOException {
        super(OpenPgpMetadata.getBuilder());

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

    protected OpenPgpMessageInputStream(@Nonnull InputStream inputStream,
                                        @Nonnull Policy policy,
                                        @Nonnull ConsumerOptions options) {
        super(OpenPgpMetadata.getBuilder());
        this.policy = policy;
        this.options = options;
        this.metadata = new MessageMetadata.Message();
        this.signatures = new Signatures(options);
        this.signatures.addDetachedSignatures(options.getDetachedSignatures());
        this.packetInputStream = new TeeBCPGInputStream(BCPGInputStream.wrap(inputStream), signatures);
    }

    private static InputStream prepareInputStream(InputStream inputStream, ConsumerOptions options, Policy policy)
            throws IOException, PGPException {
        OpenPgpInputStream openPgpIn = new OpenPgpInputStream(inputStream);
        openPgpIn.reset();

        if (openPgpIn.isBinaryOpenPgp()) {
            return openPgpIn;
        }

        if (openPgpIn.isAsciiArmored()) {
            ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(openPgpIn);
            if (armorIn.isClearText()) {
                return parseCleartextSignedMessage(armorIn, options, policy);
            } else {
                return armorIn;
            }
        } else {
            return openPgpIn;
        }
    }

    private static DecryptionStream parseCleartextSignedMessage(ArmoredInputStream armorIn, ConsumerOptions options, Policy policy)
            throws IOException, PGPException {
        MultiPassStrategy multiPassStrategy = options.getMultiPassStrategy();
        PGPSignatureList signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(armorIn, multiPassStrategy.getMessageOutputStream());

        for (PGPSignature signature : signatures) {
            options.addVerificationOfDetachedSignature(signature);
        }

        options.forceNonOpenPgpData();
        return new OpenPgpMessageInputStream(multiPassStrategy.getMessageInputStream(), policy, options);
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

        loop: // we break this when we go deeper.
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
                        break loop;
                    }

                    throw new MissingDecryptionMethodException("No working decryption method found.");

                    // Marker Packets need to be skipped and ignored
                case MARKER:
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
        automaton.next(InputAlphabet.LiteralData);
        PGPLiteralData literalData = packetInputStream.readLiteralData();
        this.metadata.setChild(new MessageMetadata.LiteralData(
                literalData.getFileName(),
                literalData.getModificationTime(),
                StreamEncoding.requireFromCode(literalData.getFormat())));
        nestedInputStream = literalData.getDataStream();
    }

    private void processCompressedData() throws IOException, PGPException {
        automaton.next(InputAlphabet.CompressedData);
        signatures.enterNesting();
        PGPCompressedData compressedData = packetInputStream.readCompressedData();
        MessageMetadata.CompressedData compressionLayer = new MessageMetadata.CompressedData(
                CompressionAlgorithm.fromId(compressedData.getAlgorithm()),
                metadata.depth + 1);
        InputStream decompressed = compressedData.getDataStream();
        nestedInputStream = new OpenPgpMessageInputStream(buffer(decompressed), options, compressionLayer, policy);
    }

    private void processOnePassSignature() throws PGPException, IOException {
        automaton.next(InputAlphabet.OnePassSignature);
        PGPOnePassSignature onePassSignature = packetInputStream.readOnePassSignature();
        signatures.addOnePassSignature(onePassSignature);
    }

    private void processSignature() throws PGPException, IOException {
        // true if Signature corresponds to OnePassSignature
        boolean isSigForOPS = automaton.peekStack() == StackAlphabet.ops;
        automaton.next(InputAlphabet.Signature);
        PGPSignature signature = packetInputStream.readSignature();
        if (isSigForOPS) {
            signatures.leaveNesting(); // TODO: Only leave nesting if all OPSs of the nesting layer are dealt with
            signatures.addCorrespondingOnePassSignature(signature, metadata, policy);
        } else {
            signatures.addPrependedSignature(signature);
        }
    }

    private boolean processEncryptedData() throws IOException, PGPException {
        automaton.next(InputAlphabet.EncryptedData);
        PGPEncryptedDataList encDataList = packetInputStream.readEncryptedDataList();

        // TODO: Replace with !encDataList.isIntegrityProtected()
        //  once BC ships it
        if (!encDataList.get(0).isIntegrityProtected()) {
            throw new MessageNotIntegrityProtectedException();
        }

        SortedESKs esks = new SortedESKs(encDataList);

        // Try session key
        if (options.getSessionKey() != null) {
            SessionKey sessionKey = options.getSessionKey();
            throwIfUnacceptable(sessionKey.getAlgorithm());

            SessionKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                    .getSessionKeyDataDecryptorFactory(sessionKey);
            MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                    sessionKey.getAlgorithm(), metadata.depth + 1);

            try {
                // TODO: Use BCs new API once shipped
                PGPEncryptedData esk = esks.all().get(0);
                if (esk instanceof PGPPBEEncryptedData) {
                    PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) esk;
                    InputStream decrypted = skesk.getDataStream(decryptorFactory);
                    encryptedData.sessionKey = sessionKey;
                    IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, skesk, options);
                    nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                    return true;
                } else if (esk instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) esk;
                    InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                    encryptedData.sessionKey = sessionKey;
                    IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, pkesk, options);
                    nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                    return true;
                } else {
                    throw new RuntimeException("Unknown ESK class type: " + esk.getClass().getName());
                }
            } catch (PGPException e) {
                // Session key mismatch?
            }
        }

        // Try passwords
        for (PGPPBEEncryptedData skesk : esks.skesks) {
            SymmetricKeyAlgorithm kekAlgorithm = SymmetricKeyAlgorithm.requireFromId(skesk.getAlgorithm());
            throwIfUnacceptable(kekAlgorithm);
            for (Passphrase passphrase : options.getDecryptionPassphrases()) {
                PBEDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                        .getPBEDataDecryptorFactory(passphrase);

                try {
                    InputStream decrypted = skesk.getDataStream(decryptorFactory);
                    SessionKey sessionKey = new SessionKey(skesk.getSessionKey(decryptorFactory));
                    throwIfUnacceptable(sessionKey.getAlgorithm());
                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                            sessionKey.getAlgorithm(), metadata.depth + 1);
                    encryptedData.sessionKey = sessionKey;
                    IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, skesk, options);
                    nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                    return true;
                } catch (UnacceptableAlgorithmException e) {
                    throw e;
                } catch (PGPException e) {
                    // Password mismatch?
                }
            }
        }

        List<Tuple<PGPSecretKey, PGPPublicKeyEncryptedData>> postponedDueToMissingPassphrase = new ArrayList<>();
        // Try (known) secret keys
        for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
            long keyId = pkesk.getKeyID();
            PGPSecretKeyRing decryptionKeys = getDecryptionKey(keyId);
            if (decryptionKeys == null) {
                continue;
            }
            PGPSecretKey secretKey = decryptionKeys.getSecretKey(keyId);

            SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeys);
            // Postpone keys with missing passphrase
            if (!protector.hasPassphraseFor(keyId)) {
                postponedDueToMissingPassphrase.add(new Tuple<>(secretKey, pkesk));
                continue;
            }

            PGPSecretKey decryptionKey = decryptionKeys.getSecretKey(keyId);
            PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(decryptionKey, protector);

            PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                    .getPublicKeyDataDecryptorFactory(privateKey);
            try {
                InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                SessionKey sessionKey = new SessionKey(pkesk.getSessionKey(decryptorFactory));
                throwIfUnacceptable(sessionKey.getAlgorithm());

                MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                        SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)),
                        metadata.depth + 1);
                encryptedData.decryptionKey = new SubkeyIdentifier(decryptionKeys, decryptionKey.getKeyID());
                encryptedData.sessionKey = sessionKey;

                IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, pkesk, options);
                nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                return true;
            } catch (UnacceptableAlgorithmException e) {
                throw e;
            } catch (PGPException e) {

            }
        }

        // try anonymous secret keys
        for (PGPPublicKeyEncryptedData pkesk : esks.anonPkesks) {
            for (Tuple<PGPSecretKeyRing, PGPSecretKey> decryptionKeyCandidate : findPotentialDecryptionKeys(pkesk)) {
                PGPSecretKey secretKey = decryptionKeyCandidate.getB();
                SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeyCandidate.getA());
                if (!protector.hasPassphraseFor(secretKey.getKeyID())) {
                    postponedDueToMissingPassphrase.add(new Tuple<>(secretKey, pkesk));
                    continue;
                }
                PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(decryptionKeyCandidate.getB(), protector);
                PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                        .getPublicKeyDataDecryptorFactory(privateKey);

                try {
                    InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                    SessionKey sessionKey = new SessionKey(pkesk.getSessionKey(decryptorFactory));
                    throwIfUnacceptable(sessionKey.getAlgorithm());

                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                            SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)),
                            metadata.depth + 1);
                    encryptedData.decryptionKey = new SubkeyIdentifier(decryptionKeyCandidate.getA(), privateKey.getKeyID());
                    encryptedData.sessionKey = sessionKey;

                    IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, pkesk, options);
                    nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                    return true;
                } catch (PGPException e) {
                    // hm :/
                }
            }
        }

        if (options.getMissingKeyPassphraseStrategy() == MissingKeyPassphraseStrategy.THROW_EXCEPTION) {
            // Non-interactive mode: Throw an exception with all locked decryption keys
            Set<SubkeyIdentifier> keyIds = new HashSet<>();
            for (Tuple<PGPSecretKey, PGPPublicKeyEncryptedData> k : postponedDueToMissingPassphrase) {
                PGPSecretKey key = k.getA();
                keyIds.add(new SubkeyIdentifier(getDecryptionKey(key.getKeyID()), key.getKeyID()));
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
                    SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKey);
                    PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, protector.getDecryptor(keyId));

                    PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                            .getPublicKeyDataDecryptorFactory(privateKey);

                    try {
                        InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                        SessionKey sessionKey = new SessionKey(pkesk.getSessionKey(decryptorFactory));
                        throwIfUnacceptable(sessionKey.getAlgorithm());

                        MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                                SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)),
                                metadata.depth + 1);
                        encryptedData.decryptionKey = new SubkeyIdentifier(decryptionKey, keyId);
                        encryptedData.sessionKey = sessionKey;

                        IntegrityProtectedInputStream integrityProtected = new IntegrityProtectedInputStream(decrypted, pkesk, options);
                        nestedInputStream = new OpenPgpMessageInputStream(buffer(integrityProtected), options, encryptedData, policy);
                        return true;
                    } catch (PGPException e) {
                        // hm :/
                    }
                }
            }
        } else {
            throw new IllegalStateException("Invalid PostponedKeysStrategy set in consumer options.");
        }

        // we did not yet succeed in decrypting any session key :/
        return false;
    }

    private PGPSecretKey getDecryptionKey(PGPSecretKeyRing decryptionKeys, long keyId) {
        KeyRingInfo info = PGPainless.inspectKeyRing(decryptionKeys);
        if (info.getEncryptionSubkeys(EncryptionPurpose.ANY).contains(info.getPublicKey(keyId))) {
            return info.getSecretKey(keyId);
        }
        return null;
    }

    private void throwIfUnacceptable(SymmetricKeyAlgorithm algorithm)
            throws UnacceptableAlgorithmException {
        if (!policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(algorithm)) {
            throw new UnacceptableAlgorithmException("Symmetric-Key algorithm " + algorithm + " is not acceptable for message decryption.");
        }
    }

    private static InputStream buffer(InputStream inputStream) {
        return new BufferedInputStream(inputStream);
    }

    private List<Tuple<PGPSecretKeyRing, PGPSecretKey>> findPotentialDecryptionKeys(PGPPublicKeyEncryptedData pkesk) {
        int algorithm = pkesk.getAlgorithm();
        List<Tuple<PGPSecretKeyRing, PGPSecretKey>> decryptionKeyCandidates = new ArrayList<>();

        for (PGPSecretKeyRing secretKeys : options.getDecryptionKeys()) {
            KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
            for (PGPPublicKey publicKey : info.getEncryptionSubkeys(EncryptionPurpose.ANY)) {
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
            return secretKeys;
        }
        return null;
    }

    @Override
    public int read() throws IOException {
        if (nestedInputStream == null) {
            automaton.assertValid();
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
                automaton.assertValid();
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
                automaton.assertValid();
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
            automaton.next(InputAlphabet.EndOfSequence);
            automaton.assertValid();
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
                } else if (esk instanceof PGPPublicKeyEncryptedData) {
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

    @Override
    public OpenPgpMetadata getResult() {
        MessageMetadata m = getMetadata();
        resultBuilder.setCompressionAlgorithm(m.getCompressionAlgorithm());
        resultBuilder.setModificationDate(m.getModificationDate());
        resultBuilder.setFileName(m.getFilename());
        resultBuilder.setFileEncoding(m.getFormat());
        resultBuilder.setSessionKey(m.getSessionKey());
        resultBuilder.setDecryptionKey(m.getDecryptionKey());

        for (SignatureVerification accepted : m.getVerifiedDetachedSignatures()) {
            resultBuilder.addVerifiedDetachedSignature(accepted);
        }
        for (SignatureVerification.Failure rejected : m.getRejectedDetachedSignatures()) {
            resultBuilder.addInvalidDetachedSignature(rejected.getSignatureVerification(), rejected.getValidationException());
        }

        for (SignatureVerification accepted : m.getVerifiedInlineSignatures()) {
            resultBuilder.addVerifiedInbandSignature(accepted);
        }
        for (SignatureVerification.Failure rejected : m.getRejectedInlineSignatures()) {
            resultBuilder.addInvalidInbandSignature(rejected.getSignatureVerification(), rejected.getValidationException());
        }

        return resultBuilder.build();
    }

    static void log(String message) {
        LOGGER.debug(message);
        // CHECKSTYLE:OFF
        System.out.println(message);
        // CHECKSTYLE:ON
    }

    static void log(String message, Throwable e) {
        log(message);
        // CHECKSTYLE:OFF
        e.printStackTrace();
        // CHECKSTYLE:ON
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
            if (check != null) {
                detachedSignatures.add(check);
            }
        }

        void addPrependedSignature(PGPSignature signature) {
            SignatureCheck check = initializeSignature(signature);
            if (check != null) {
                this.prependedSignatures.add(check);
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
            for (int i = onePassSignatures.size() - 1; i >= 0; i--) {
                OnePassSignatureCheck onePassSignature = onePassSignatures.get(i);
                if (onePassSignature.getOnePassSignature().getKeyID() != signature.getKeyID()) {
                    continue;
                }

                if (onePassSignature.getSignature() != null) {
                    continue;
                }

                onePassSignature.setSignature(signature);
                SignatureVerification verification = new SignatureVerification(signature,
                        new SubkeyIdentifier(onePassSignature.getVerificationKeys(), onePassSignature.getOnePassSignature().getKeyID()));

                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(signature);
                    SignatureVerifier.verifyOnePassSignature(signature, onePassSignature.getVerificationKeys().getPublicKey(signature.getKeyID()), onePassSignature, policy);
                    layer.addVerifiedOnePassSignature(verification);
                } catch (SignatureValidationException e) {
                    layer.addRejectedOnePassSignature(new SignatureVerification.Failure(verification, e));
                }
                break;
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
            for (PGPPublicKeyRing cert : options.getCertificates()) {
                PGPPublicKey verificationKey = cert.getPublicKey(keyId);
                if (verificationKey != null) {
                    return cert;
                }
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
                    SignatureVerifier.verifyInitializedSignature(
                            detached.getSignature(),
                            detached.getSigningKeyRing().getPublicKey(detached.getSigningKeyIdentifier().getKeyId()),
                            policy, detached.getSignature().getCreationTime());
                    layer.addVerifiedDetachedSignature(verification);
                } catch (SignatureValidationException e) {
                    layer.addRejectedDetachedSignature(new SignatureVerification.Failure(verification, e));
                }
            }

            for (SignatureCheck prepended : prependedSignatures) {
                SignatureVerification verification = new SignatureVerification(prepended.getSignature(), prepended.getSigningKeyIdentifier());
                try {
                    SignatureValidator.signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter())
                            .verify(prepended.getSignature());
                    SignatureVerifier.verifyInitializedSignature(
                            prepended.getSignature(),
                            prepended.getSigningKeyRing().getPublicKey(prepended.getSigningKeyIdentifier().getKeyId()),
                            policy, prepended.getSignature().getCreationTime());
                    layer.addVerifiedPrependedSignature(verification);
                } catch (SignatureValidationException e) {
                    layer.addRejectedPrependedSignature(new SignatureVerification.Failure(verification, e));
                }
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
