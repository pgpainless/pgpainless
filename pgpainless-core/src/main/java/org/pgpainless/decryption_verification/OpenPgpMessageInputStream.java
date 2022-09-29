// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Stack;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Hex;
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
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenPgpMessageInputStream extends InputStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenPgpMessageInputStream.class);

    // Options to consume the data
    protected final ConsumerOptions options;
    protected final OpenPgpMetadata.Builder resultBuilder;
    // Pushdown Automaton to verify validity of OpenPGP packet sequence in an OpenPGP message
    protected final PDA automaton = new PDA();
    // InputStream of OpenPGP packets of the current layer
    protected final BCPGInputStream packetInputStream;
    // InputStream of a nested data packet
    protected InputStream nestedInputStream;

    private boolean closed = false;

    private final Signatures signatures;
    private MessageMetadata.Layer metadata;

    public OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options)
            throws IOException, PGPException {
        this(inputStream, options, new MessageMetadata.Message());
    }

    OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options, MessageMetadata.Layer metadata)
            throws PGPException, IOException {

        this.options = options;
        this.metadata = metadata;
        this.resultBuilder = OpenPgpMetadata.getBuilder();
        this.signatures = new Signatures(options);

        // Add detached signatures only on the outermost OpenPgpMessageInputStream
        if (metadata instanceof MessageMetadata.Message) {
            this.signatures.addDetachedSignatures(options.getDetachedSignatures());
        }

        BCPGInputStream bcpg = BCPGInputStream.wrap(inputStream);
        this.packetInputStream = new TeeBCPGInputStream(bcpg, signatures);

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
        int tag;
        loop: while ((tag = nextTag()) != -1) {
            OpenPgpPacket nextPacket;
            try {
                nextPacket = OpenPgpPacket.requireFromTag(tag);
            } catch (NoSuchElementException e) {
                log("Invalid tag: " + tag);
                throw e;
            }
            log(nextPacket.toString());
            signatures.nextPacket(nextPacket);
            switch (nextPacket) {

                // Literal Data - the literal data content is the new input stream
                case LIT:
                    automaton.next(InputAlphabet.LiteralData);
                    processLiteralData();
                    break loop;

                // Compressed Data - the content contains another OpenPGP message
                case COMP:
                    automaton.next(InputAlphabet.CompressedData);
                    signatures.commitNested();
                    processCompressedData();
                    break loop;

                // One Pass Signature
                case OPS:
                    automaton.next(InputAlphabet.OnePassSignatures);
                    PGPOnePassSignature onePassSignature = readOnePassSignature();
                    signatures.addOnePassSignature(onePassSignature);
                    break;

                // Signature - either prepended to the message, or corresponding to a One Pass Signature
                case SIG:
                    boolean isSigForOPS = automaton.peekStack() == StackAlphabet.ops;
                    automaton.next(InputAlphabet.Signatures);

                    PGPSignature signature = readSignature();
                    processSignature(signature, isSigForOPS);

                    break;

                // Encrypted Data (ESKs and SED/SEIPD are parsed the same by BC)
                case PKESK:
                case SKESK:
                case SED:
                case SEIPD:
                    automaton.next(InputAlphabet.EncryptedData);
                    if (processEncryptedData()) {
                        break loop;
                    }

                    throw new MissingDecryptionMethodException("No working decryption method found.");

                    // Marker Packets need to be skipped and ignored
                case MARKER:
                    packetInputStream.readPacket(); // skip
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

    private void processSignature(PGPSignature signature, boolean isSigForOPS) {
        if (isSigForOPS) {
            signatures.popNested();
            signatures.addCorrespondingOnePassSignature(signature);
        } else {
            signatures.addPrependedSignature(signature);
        }
    }

    private void processCompressedData() throws IOException, PGPException {
        PGPCompressedData compressedData = new PGPCompressedData(packetInputStream);
        MessageMetadata.CompressedData compressionLayer = new MessageMetadata.CompressedData(
                CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
        nestedInputStream = new OpenPgpMessageInputStream(compressedData.getDataStream(), options, compressionLayer);
    }

    private void processLiteralData() throws IOException {
        PGPLiteralData literalData = new PGPLiteralData(packetInputStream);
        this.metadata.setChild(new MessageMetadata.LiteralData(literalData.getFileName(), literalData.getModificationTime(),
                StreamEncoding.requireFromCode(literalData.getFormat())));
        nestedInputStream = literalData.getDataStream();
    }

    private void debugEncryptedData() throws PGPException, IOException {
        PGPEncryptedDataList encDataList = new PGPEncryptedDataList(packetInputStream);

        // TODO: Replace with !encDataList.isIntegrityProtected()
        if (!encDataList.get(0).isIntegrityProtected()) {
            throw new MessageNotIntegrityProtectedException();
        }

        SortedESKs esks = new SortedESKs(encDataList);
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
                InputStream decoder = PGPUtil.getDecoderStream(decrypted);
                PGPObjectFactory objectFactory = ImplementationFactory.getInstance()
                        .getPGPObjectFactory(decoder);
                objectFactory.nextObject();
                objectFactory.nextObject();
                objectFactory.nextObject();
            } catch (PGPException e) {
                // hm :/
            }
        }
    }

    private boolean processEncryptedData() throws IOException, PGPException {
        PGPEncryptedDataList encDataList = new PGPEncryptedDataList(packetInputStream);

        // TODO: Replace with !encDataList.isIntegrityProtected()
        if (!encDataList.get(0).isIntegrityProtected()) {
            throw new MessageNotIntegrityProtectedException();
        }

        SortedESKs esks = new SortedESKs(encDataList);

        // Try session key
        if (options.getSessionKey() != null) {
            SessionKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                    .getSessionKeyDataDecryptorFactory(options.getSessionKey());
            // TODO: Replace with encDataList.addSessionKeyDecryptionMethod(sessionKey)
            PGPEncryptedData esk = esks.all().get(0);
            try {
                MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(options.getSessionKey().getAlgorithm());
                if (esk instanceof PGPPBEEncryptedData) {
                    PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) esk;
                    nestedInputStream = new OpenPgpMessageInputStream(skesk.getDataStream(decryptorFactory), options, encryptedData);
                    return true;
                } else if (esk instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) esk;
                    nestedInputStream = new OpenPgpMessageInputStream(pkesk.getDataStream(decryptorFactory), options, encryptedData);
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
            for (Passphrase passphrase : options.getDecryptionPassphrases()) {
                PBEDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                        .getPBEDataDecryptorFactory(passphrase);
                try {
                    InputStream decrypted = skesk.getDataStream(decryptorFactory);
                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                            SymmetricKeyAlgorithm.requireFromId(skesk.getSymmetricAlgorithm(decryptorFactory)));
                    nestedInputStream = new OpenPgpMessageInputStream(decrypted, options, encryptedData);
                    return true;
                } catch (PGPException e) {
                    // password mismatch? Try next password
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
                MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                        SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)));

                nestedInputStream = new OpenPgpMessageInputStream(PGPUtil.getDecoderStream(decrypted), options, encryptedData);
                return true;
            } catch (PGPException e) {
                // hm :/
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
                    MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(
                            SymmetricKeyAlgorithm.requireFromId(pkesk.getSymmetricAlgorithm(decryptorFactory)));
                    nestedInputStream = new OpenPgpMessageInputStream(decrypted, options, encryptedData);
                    return true;
                } catch (PGPException e) {
                    // hm :/
                }
            }
        }

        // we did not yet succeed in decrypting any session key :/
        return false;
    }

    private int nextTag() throws IOException {
        try {
            return packetInputStream.nextPacketTag();
        } catch (IOException e) {
            if ("Stream closed".equals(e.getMessage())) {
                // ZipInflater Streams sometimes close under our feet -.-
                // Therefore we catch resulting IOEs and return -1 instead.
                return -1;
            }
            throw e;
        }
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

    private PGPOnePassSignature readOnePassSignature()
            throws PGPException, IOException {
        return new PGPOnePassSignature(packetInputStream);
    }

    private PGPSignature readSignature()
            throws PGPException, IOException {
        return new PGPSignature(packetInputStream);
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
            signatures.finish();
        }
        return r;
    }

    @Override
    public int read(byte[] b, int off, int len)
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
            signatures.finish();
        }
        return r;
    }

    @Override
    public void close() throws IOException {
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
        closed = true;
    }

    private void collectMetadata() {
        if (nestedInputStream instanceof OpenPgpMessageInputStream) {
            OpenPgpMessageInputStream child = (OpenPgpMessageInputStream) nestedInputStream;
            MessageMetadata.Layer childLayer = child.metadata;
            this.metadata.setChild((MessageMetadata.Nested) childLayer);
        }
    }

    public MessageMetadata getMetadata() {
        if (!closed) {
            throw new IllegalStateException("Stream must be closed before access to metadata can be granted.");
        }
        return new MessageMetadata((MessageMetadata.Message) metadata);
    }

    private static class SortedESKs {

        private List<PGPPBEEncryptedData> skesks = new ArrayList<>();
        private List<PGPPublicKeyEncryptedData> pkesks = new ArrayList<>();
        private List<PGPPublicKeyEncryptedData> anonPkesks = new ArrayList<>();

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

    // TODO: In 'OPS LIT("Foo") SIG', OPS is only updated with "Foo"
    //  In 'OPS[1] OPS LIT("Foo") SIG SIG', OPS[1] (nested) is updated with OPS LIT("Foo") SIG.
    //  Therefore, we need to handle the innermost signature layer differently when updating with Literal data.
    //  For this we might want to provide two update entries into the Signatures class, one for OpenPGP packets and one
    //  for literal data. UUUUUGLY!!!!
    private static final class Signatures extends OutputStream {
        final ConsumerOptions options;
        final List<PGPSignature> detachedSignatures;
        final List<PGPSignature> prependedSignatures;
        final List<OPS> onePassSignatures;
        final Stack<List<OPS>> opsUpdateStack;
        List<OPS> literalOPS = new ArrayList<>();
        final List<PGPSignature> correspondingSignatures;

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
            initialize(signature, certificate, keyId);
            this.detachedSignatures.add(signature);
        }

        void addPrependedSignature(PGPSignature signature) {
            long keyId = SignatureUtils.determineIssuerKeyId(signature);
            PGPPublicKeyRing certificate = findCertificate(keyId);
            initialize(signature, certificate, keyId);
            this.prependedSignatures.add(signature);
        }

        void addOnePassSignature(PGPOnePassSignature signature) {
            PGPPublicKeyRing certificate = findCertificate(signature.getKeyID());
            OPS ops = new OPS(signature);
            ops.init(certificate);
            onePassSignatures.add(ops);

            literalOPS.add(ops);
            if (signature.isContaining()) {
                commitNested();
            }
        }

        void addCorrespondingOnePassSignature(PGPSignature signature) {
            for (int i = onePassSignatures.size() - 1; i >= 0; i--) {
                OPS onePassSignature = onePassSignatures.get(i);
                if (onePassSignature.signature.getKeyID() != signature.getKeyID()) {
                    continue;
                }
                if (onePassSignature.finished) {
                    continue;
                }

                boolean verified = onePassSignature.verify(signature);
                log("One-Pass-Signature by " + Long.toHexString(onePassSignature.signature.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
                System.out.println(onePassSignature);
                break;
            }
        }

        void commitNested() {
            opsUpdateStack.push(literalOPS);
            literalOPS = new ArrayList<>();
        }

        void popNested() {
            if (opsUpdateStack.isEmpty()) {
                return;
            }
            opsUpdateStack.pop();
        }

        private void initialize(PGPSignature signature, PGPPublicKeyRing certificate, long keyId) {
            if (certificate == null) {
                // SHIT
                return;
            }
            PGPContentVerifierBuilderProvider verifierProvider = ImplementationFactory.getInstance()
                    .getPGPContentVerifierBuilderProvider();
            try {
                signature.init(verifierProvider, certificate.getPublicKey(keyId));
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
        }

        private static void initialize(PGPOnePassSignature ops, PGPPublicKeyRing certificate) {
            if (certificate == null) {
                return;
            }
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
            for (OPS ops : literalOPS) {
                ops.update(b);
            }

            for (PGPSignature detached : detachedSignatures) {
                detached.update(b);
            }
        }

        public void updateLiteral(byte[] b, int off, int len) {
            for (OPS ops : literalOPS) {
                ops.update(b, off, len);
            }

            for (PGPSignature detached : detachedSignatures) {
                detached.update(b, off, len);
            }
        }

        public void updatePacket(byte b) {
            for (List<OPS> nestedOPSs : opsUpdateStack) {
                for (OPS ops : nestedOPSs) {
                    ops.update(b);
                }
            }
        }

        public void updatePacket(byte[] buf, int off, int len) {
            for (int i = opsUpdateStack.size() - 1; i >= 0; i--) {
                List<OPS> nestedOPSs = opsUpdateStack.get(i);
                for (OPS ops : nestedOPSs) {
                    ops.update(buf, off, len);
                }
            }
        }

        public void finish() {
            for (PGPSignature detached : detachedSignatures) {
                boolean verified = false;
                try {
                    verified = detached.verify();
                } catch (PGPException e) {
                    log("Cannot verify detached signature.", e);
                }
                log("Detached Signature by " + Long.toHexString(detached.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
            }

            for (PGPSignature prepended : prependedSignatures) {
                boolean verified = false;
                try {
                    verified = prepended.verify();
                } catch (PGPException e) {
                    log("Cannot verify prepended signature.", e);
                }
                log("Prepended Signature by " + Long.toHexString(prepended.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
            }
        }

        @Override
        public void write(int b) {
            updatePacket((byte) b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            updatePacket(b, off, len);
        }

        public void nextPacket(OpenPgpPacket nextPacket) {
            if (nextPacket == OpenPgpPacket.LIT) {
                if (literalOPS.isEmpty() && !opsUpdateStack.isEmpty()) {
                    literalOPS = opsUpdateStack.pop();
                }
            }
        }

        static class OPS {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            PGPOnePassSignature signature;
            boolean finished;
            boolean valid;

            public OPS(PGPOnePassSignature signature) {
                this.signature = signature;
            }

            public void init(PGPPublicKeyRing certificate) {
                initialize(signature, certificate);
            }

            public boolean verify(PGPSignature signature) {
                if (this.signature.getKeyID() != signature.getKeyID()) {
                    // nope
                    return false;
                }
                finished = true;
                try {
                    valid = this.signature.verify(signature);
                } catch (PGPException e) {
                    log("Cannot verify OPS " + signature.getKeyID());
                }
                return valid;
            }

            public void update(byte b) {
                if (finished) {
                    log("Updating finished sig!");
                    return;
                }
                signature.update(b);
                bytes.write(b);
            }

            public void update(byte[] bytes, int off, int len) {
                if (finished) {
                    log("Updating finished sig!");
                    return;
                }
                signature.update(bytes, off, len);
                this.bytes.write(bytes, off, len);
            }

            @Override
            public String toString() {
                String OPS = "c40d03000a01fbfcc82a015e733001";
                String LIT_H = "cb28620000000000";
                String LIT = "656e637279707420e28898207369676e20e28898207369676e20e28898207369676e";
                String SIG1 = "c2c10400010a006f058262c806350910fbfcc82a015e7330471400000000001e002073616c74406e6f746174696f6e732e736571756f69612d7067702e6f7267b0409ed8ea96dac66447bdff5b7b60c9f80a0ab91d257029153dc3b6d8c27b98162104d1a66e1a23b182c9980f788cfbfcc82a015e7330000029640c00846b5096d92474fd446cc7edaf9f14572cab93a80e12384c1e829f95debc6e8373c2ce5402be53dc1a18cf92a0ed909e0fb38855713ef8ffb13502ffac7c830fa254cc1aa6c666a97b0cc3bc176538f6913d3b8e8981a65cc42df10e0f39e4d0a06dfe961437b59a71892f4fca1116aed15123ea0d86a7b2ce47dd9d3ef22d920631bc011e82babe03ad5d72b3ba7f95bf646f20ccf6f7a4d95de37397c76c7d53741458e51ab6074007f61181c7b88b7c98f5b7510c8dfa3be01f4841501679478b15c5249d928e2a10d15ec63efa1500b994d5bfb32ffb174a976116930eb97a111e6dfd4c5e43e04a5d76ba74806a62fda63a8c3f53f6eebaf852892340e81dd08bbf348454a2cf525aeb512cf33aeeee78465ee4c442e41cc45ac4e3bb0c3333677aa60332ee7f464d9020f8554b82d619872477cca18d8431888f4ae8abe5894e9720f759c410cd7991db12703dc147040dd0d3758223e0b75de6ceae49c1a0c2c45efedeb7114ae785cc886afdc45c82172e4476e1ab5b86dc4314dd76";
                String SIG2 = "c2c10400010a006f058262c806350910fbfcc82a015e7330471400000000001e002073616c74406e6f746174696f6e732e736571756f69612d7067702e6f7267a4d9c117dc7ba3a7e9270856f128d2ab271743eac3cb5750b22a89bd5fd60753162104d1a66e1a23b182c9980f788cfbfcc82a015e73300000b8400bff796c20fa8b25ff7a42686338e06417a2966e85a0fc2723c928bef6cd19d34cf5e7d55ada33080613012dadb79e0278e59d9e7ed7d2d6102912a5f768c2e75b60099225c3d8bfe0c123240188b80dbee89b9b3bd5b13ccc662abc37e2129b6968adac9aba43aa778c0fe4fe337591ee87a96a29a013debc83555293c877144fc676aa1b03782c501949521a320adf6ad96c4f2e036b52a18369c637fdc49033696a84d03a69580b953187fce5aca6fb26fc8815da9f3b513bfe8e304f33ecb4b521aeb7d09c4a284ea66123bd0d6a358b2526d762ca110e1f7f20b3038d774b64d5cfd34e2213765828359d7afc5bf24d5270e99d80c3c1568fa01624b6ea1e9ce4e6890ce9bacf6611a45d41e2671f68f5b096446bf08d27ce75608425b2e3ab92146229ad1fcd8224aca5b5f73960506e7df07bfbf3664348e8ecbfb2eb467b9cfe412cb377a6ee2eb5fd11be9cf9208fe9a74c296f52cfa02a1eb0519ad9a8349bf6ccd6495feb7e391451bf96e08a0798883dee5974e47cbf3b51f111b6d3";
                    String out = signature.getKeyID() + " last=" + signature.isContaining() + "\n";

                    String hex = Hex.toHexString(bytes.toByteArray());
                    while (hex.contains(OPS)) {
                        hex = hex.replace(OPS, "[OPS]");
                    }
                    while (hex.contains(LIT_H)) {
                        hex = hex.replace(LIT_H, "[LIT]");
                    }
                    while (hex.contains(LIT)) {
                        hex = hex.replace(LIT, "<content>");
                    }
                    while (hex.contains(SIG1)) {
                        hex = hex.replace(SIG1, "[SIG1]");
                    }
                    while (hex.contains(SIG2)) {
                        hex = hex.replace(SIG2, "[SIG2]");
                    }

                    return out + hex;
            }
        }
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
