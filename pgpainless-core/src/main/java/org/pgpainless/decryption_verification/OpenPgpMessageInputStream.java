// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Stack;
import javax.annotation.Nonnull;

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
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.exception.UnacceptableAlgorithmException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.SignatureValidator;
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
        this(inputStream, options, new MessageMetadata.Message(), policy);
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
                CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
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
            MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(sessionKey.getAlgorithm());

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
                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(sessionKey.getAlgorithm());
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

        // Try (known) secret keys
        for (PGPPublicKeyEncryptedData pkesk : esks.pkesks) {
            long keyId = pkesk.getKeyID();
            PGPSecretKeyRing decryptionKeys = getDecryptionKey(keyId);
            if (decryptionKeys == null) {
                continue;
            }
            SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeys);
            PGPSecretKey decryptionKey = decryptionKeys.getSecretKey(keyId);
            PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(decryptionKey, protector);

            PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                    .getPublicKeyDataDecryptorFactory(privateKey);
            try {
                InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                SessionKey sessionKey = new SessionKey(pkesk.getSessionKey(decryptorFactory));
                throwIfUnacceptable(sessionKey.getAlgorithm());

                MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                        SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)));
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
                SecretKeyRingProtector protector = options.getSecretKeyProtector(decryptionKeyCandidate.getA());
                PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(decryptionKeyCandidate.getB(), protector);
                PublicKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                        .getPublicKeyDataDecryptorFactory(privateKey);

                try {
                    InputStream decrypted = pkesk.getDataStream(decryptorFactory);
                    SessionKey sessionKey = new SessionKey(pkesk.getSessionKey(decryptorFactory));
                    throwIfUnacceptable(sessionKey.getAlgorithm());

                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                            SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)));
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

        // we did not yet succeed in decrypting any session key :/
        return false;
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

            try {
                consumePackets();
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
            signatures.finish(metadata, policy);
        }
        return r;
    }

    @Override
    public int read(@Nonnull byte[] b, int off, int len)
            throws IOException {

        if (nestedInputStream == null) {
            automaton.assertValid();
            return -1;
        }

        int r = nestedInputStream.read(b, off, len);
        if (r != -1) {
            signatures.updateLiteral(b, off, r);
        }
        else  {
            nestedInputStream.close();
            collectMetadata();
            nestedInputStream = null;

            try {
                consumePackets();
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
            signatures.finish(metadata, policy);
        }
        return r;
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (closed) {
            automaton.assertValid();
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

        automaton.next(InputAlphabet.EndOfSequence);
        automaton.assertValid();
        packetInputStream.close();
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

    // In 'OPS LIT("Foo") SIG', OPS is only updated with "Foo"
    // In 'OPS[1] OPS LIT("Foo") SIG SIG', OPS[1] (nested) is updated with OPS LIT("Foo") SIG.
    // Therefore, we need to handle the innermost signature layer differently when updating with Literal data.
    // Furthermore, For 'OPS COMP(LIT("Foo")) SIG', the signature is updated with "Foo". CHAOS!!!
    private static final class Signatures extends OutputStream {
        final ConsumerOptions options;
        final List<DetachedOrPrependedSignature> detachedSignatures;
        final List<DetachedOrPrependedSignature> prependedSignatures;
        final List<OnePassSignature> onePassSignatures;
        final Stack<List<OnePassSignature>> opsUpdateStack;
        List<OnePassSignature> literalOPS = new ArrayList<>();
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
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing certificate = findCertificate(keyId);

            if (certificate != null) {
                initialize(signature, certificate, keyId);
                this.detachedSignatures.add(new DetachedOrPrependedSignature(signature, certificate, keyId));
            }
        }

        void addPrependedSignature(PGPSignature signature) {
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing certificate = findCertificate(keyId);

            if (certificate != null) {
                initialize(signature, certificate, keyId);
                this.prependedSignatures.add(new DetachedOrPrependedSignature(signature, certificate, keyId));
            }
        }

        void addOnePassSignature(PGPOnePassSignature signature) {
            PGPPublicKeyRing certificate = findCertificate(signature.getKeyID());

            if (certificate != null) {
                OnePassSignature ops = new OnePassSignature(signature, certificate, signature.getKeyID());
                ops.init(certificate);
                onePassSignatures.add(ops);

                literalOPS.add(ops);
            }
            if (signature.isContaining()) {
                enterNesting();
            }
        }

        void addCorrespondingOnePassSignature(PGPSignature signature, MessageMetadata.Layer layer, Policy policy) {
            for (int i = onePassSignatures.size() - 1; i >= 0; i--) {
                OnePassSignature onePassSignature = onePassSignatures.get(i);
                if (onePassSignature.opSignature.getKeyID() != signature.getKeyID()) {
                    continue;
                }
                if (onePassSignature.finished) {
                    continue;
                }

                boolean correct = onePassSignature.verify(signature);
                SignatureVerification verification = new SignatureVerification(signature,
                        new SubkeyIdentifier(onePassSignature.certificate, onePassSignature.keyId));
                if (correct) {
                    PGPPublicKey signingKey = onePassSignature.certificate.getPublicKey(onePassSignature.keyId);
                    try {
                        checkSignatureValidity(signature, signingKey, policy);
                        layer.addVerifiedOnePassSignature(verification);
                    } catch (SignatureValidationException e) {
                        layer.addRejectedOnePassSignature(new SignatureVerification.Failure(verification, e));
                    }
                } else {
                    layer.addRejectedOnePassSignature(new SignatureVerification.Failure(verification,
                            new SignatureValidationException("Bad Signature.")));
                }
                break;
            }
        }

        boolean checkSignatureValidity(PGPSignature signature, PGPPublicKey signingKey, Policy policy) throws SignatureValidationException {
            SignatureValidator.wasPossiblyMadeByKey(signingKey).verify(signature);
            SignatureValidator.signatureStructureIsAcceptable(signingKey, policy).verify(signature);
            SignatureValidator.signatureIsEffective().verify(signature);
            return true;
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
            for (OnePassSignature ops : literalOPS) {
                ops.update(b);
            }

            for (DetachedOrPrependedSignature detached : detachedSignatures) {
                detached.update(b);
            }

            for (DetachedOrPrependedSignature prepended : prependedSignatures) {
                prepended.update(b);
            }
        }

        public void updateLiteral(byte[] b, int off, int len) {
            for (OnePassSignature ops : literalOPS) {
                ops.update(b, off, len);
            }

            for (DetachedOrPrependedSignature detached : detachedSignatures) {
                detached.update(b, off, len);
            }

            for (DetachedOrPrependedSignature prepended : prependedSignatures) {
                prepended.update(b, off, len);
            }
        }

        public void updatePacket(byte b) {
            for (int i = opsUpdateStack.size() - 1; i >= 0; i--) {
                List<OnePassSignature> nestedOPSs = opsUpdateStack.get(i);
                for (OnePassSignature ops : nestedOPSs) {
                    ops.update(b);
                }
            }
        }

        public void updatePacket(byte[] buf, int off, int len) {
            for (int i = opsUpdateStack.size() - 1; i >= 0; i--) {
                List<OnePassSignature> nestedOPSs = opsUpdateStack.get(i);
                for (OnePassSignature ops : nestedOPSs) {
                    ops.update(buf, off, len);
                }
            }
        }

        public void finish(MessageMetadata.Layer layer, Policy policy) {
            for (DetachedOrPrependedSignature detached : detachedSignatures) {
                boolean correct = detached.verify();
                SignatureVerification verification = new SignatureVerification(
                        detached.signature, new SubkeyIdentifier(detached.certificate, detached.keyId));
                if (correct) {
                    try {
                        PGPPublicKey signingKey = detached.certificate.getPublicKey(detached.keyId);
                        checkSignatureValidity(detached.signature, signingKey, policy);
                        layer.addVerifiedDetachedSignature(verification);
                    } catch (SignatureValidationException e) {
                        layer.addRejectedDetachedSignature(new SignatureVerification.Failure(verification, e));
                    }
                } else {
                    layer.addRejectedDetachedSignature(new SignatureVerification.Failure(
                            verification, new SignatureValidationException("Incorrect Signature.")));
                }
            }

            for (DetachedOrPrependedSignature prepended : prependedSignatures) {
                boolean correct = prepended.verify();
                SignatureVerification verification = new SignatureVerification(
                        prepended.signature, new SubkeyIdentifier(prepended.certificate, prepended.keyId));
                if (correct) {
                    try {
                        PGPPublicKey signingKey = prepended.certificate.getPublicKey(prepended.keyId);
                        checkSignatureValidity(prepended.signature, signingKey, policy);
                        layer.addVerifiedPrependedSignature(verification);
                    } catch (SignatureValidationException e) {
                        layer.addRejectedPrependedSignature(new SignatureVerification.Failure(verification, e));
                    }
                } else {
                    layer.addRejectedPrependedSignature(new SignatureVerification.Failure(
                            verification, new SignatureValidationException("Incorrect Signature.")));
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

        static class DetachedOrPrependedSignature {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            PGPSignature signature;
            PGPPublicKeyRing certificate;
            long keyId;
            boolean finished;
            boolean valid;

            DetachedOrPrependedSignature(PGPSignature signature, PGPPublicKeyRing certificate, long keyId) {
                this.signature = signature;
                this.certificate = certificate;
                this.keyId = keyId;
            }

            public void init(PGPPublicKeyRing certificate) {
                initialize(signature, certificate, signature.getKeyID());
            }

            public boolean verify() {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }
                finished = true;
                try {
                    valid = this.signature.verify();
                } catch (PGPException e) {
                    log("Cannot verify SIG " + signature.getKeyID());
                }
                return valid;
            }

            public void update(byte b) {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }
                signature.update(b);
                bytes.write(b);
            }

            public void update(byte[] bytes, int off, int len) {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }
                signature.update(bytes, off, len);
                this.bytes.write(bytes, off, len);
            }
        }

        static class OnePassSignature {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            PGPOnePassSignature opSignature;
            PGPSignature signature;
            PGPPublicKeyRing certificate;
            long keyId;
            boolean finished;
            boolean valid;

            OnePassSignature(PGPOnePassSignature signature, PGPPublicKeyRing certificate, long keyId) {
                this.opSignature = signature;
                this.certificate = certificate;
                this.keyId = keyId;
            }

            public void init(PGPPublicKeyRing certificate) {
                initialize(opSignature, certificate);
            }

            public boolean verify(PGPSignature signature) {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }

                if (this.opSignature.getKeyID() != signature.getKeyID()) {
                    // nope
                    return false;
                }
                this.signature = signature;
                finished = true;
                try {
                    valid = this.opSignature.verify(signature);
                } catch (PGPException e) {
                    log("Cannot verify OPS " + signature.getKeyID());
                }
                return valid;
            }

            public void update(byte b) {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }
                opSignature.update(b);
                bytes.write(b);
            }

            public void update(byte[] bytes, int off, int len) {
                if (finished) {
                    throw new IllegalStateException("Already finished.");
                }
                opSignature.update(bytes, off, len);
                this.bytes.write(bytes, off, len);
            }
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
}
