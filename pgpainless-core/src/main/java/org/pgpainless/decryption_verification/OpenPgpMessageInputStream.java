// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SignaturePacket;
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
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.pqc.crypto.rainbow.Layer;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.OpenPgpPacket;
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
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class OpenPgpMessageInputStream extends InputStream {

    protected final PDA automaton = new PDA();
    protected final ConsumerOptions options;
    protected final OpenPgpMetadata.Builder resultBuilder;
    protected final BCPGInputStream bcpgIn;
    protected InputStream in;

    private boolean closed = false;

    private Signatures signatures;
    private LayerMetadata layerMetadata;

    public OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options)
            throws IOException, PGPException {
        this(inputStream, options, null);
    }

    OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options, LayerMetadata layerMetadata)
            throws PGPException, IOException {
        // TODO: Use BCPGInputStream.wrap(inputStream);
        if (inputStream instanceof BCPGInputStream) {
            this.bcpgIn = (BCPGInputStream) inputStream;
        } else {
            this.bcpgIn = new BCPGInputStream(inputStream);
        }

        this.options = options;
        this.resultBuilder = OpenPgpMetadata.getBuilder();
        this.signatures = new Signatures(options);
        this.signatures.addDetachedSignatures(options.getDetachedSignatures());

        consumePackets();
    }

    static class LayerMetadata {

        private CompressionAlgorithm compressionAlgorithm;
        private SymmetricKeyAlgorithm symmetricKeyAlgorithm;
        private LayerMetadata child;

        public LayerMetadata setCompressionAlgorithm(CompressionAlgorithm algorithm) {
            this.compressionAlgorithm = algorithm;
            return this;
        }

        public LayerMetadata setSymmetricEncryptionAlgorithm(SymmetricKeyAlgorithm algorithm) {
            this.symmetricKeyAlgorithm = algorithm;
            return this;
        }

        public LayerMetadata setChild(LayerMetadata child) {
            this.child = child;
            return this;
        }
    }

    /**
     * This method consumes OpenPGP packets from the current {@link BCPGInputStream}.
     * Once it reaches a "nested" OpenPGP packet (Literal Data, Compressed Data, Encrypted Data), it sets <pre>in</pre>
     * to the nested stream and breaks the loop.
     * The nested stream is either a simple {@link InputStream} (in case of Literal Data), or another
     * {@link OpenPgpMessageInputStream} in case of Compressed and Encrypted Data.
     *
     * @throws IOException
     * @throws PGPException
     */
    private void consumePackets()
            throws IOException, PGPException {
        System.out.println("Walk " + automaton);
        int tag;
        loop: while ((tag = nextTag()) != -1) {
            OpenPgpPacket nextPacket = OpenPgpPacket.requireFromTag(tag);
            System.out.println(nextPacket);
            switch (nextPacket) {

                // Literal Data - the literal data content is the new input stream
                case LIT:
                    automaton.next(InputAlphabet.LiteralData);
                    PGPLiteralData literalData = new PGPLiteralData(bcpgIn);
                    in = literalData.getDataStream();
                    break loop;

                // Compressed Data - the content contains another OpenPGP message
                case COMP:
                    automaton.next(InputAlphabet.CompressedData);
                    PGPCompressedData compressedData = new PGPCompressedData(bcpgIn);
                    LayerMetadata compressionLayer = new LayerMetadata();
                    compressionLayer.setCompressionAlgorithm(CompressionAlgorithm.fromId(compressedData.getAlgorithm()));
                    in = new OpenPgpMessageInputStream(compressedData.getDataStream(), options, compressionLayer);
                    break loop;

                // One Pass Signatures
                case OPS:
                    automaton.next(InputAlphabet.OnePassSignatures);
                    signatures.addOnePassSignatures(readOnePassSignatures());
                    break;

                // Signatures - either prepended to the message, or corresponding to the One Pass Signatures
                case SIG:
                    boolean isSigForOPS = automaton.peekStack() == StackAlphabet.ops;
                    automaton.next(InputAlphabet.Signatures);
                    PGPSignatureList signatureList = readSignatures();
                    if (isSigForOPS) {
                        signatures.addOnePassCorrespondingSignatures(signatureList);
                    } else {
                        signatures.addPrependedSignatures(signatureList);
                    }
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
                    bcpgIn.readPacket(); // skip
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

    private boolean processEncryptedData() throws IOException, PGPException {
        PGPEncryptedDataList encDataList = new PGPEncryptedDataList(bcpgIn);

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
                if (esk instanceof PGPPBEEncryptedData) {
                    PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) esk;
                    in = skesk.getDataStream(decryptorFactory);
                    return true;
                } else if (esk instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) esk;
                    in = pkesk.getDataStream(decryptorFactory);
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
                    in = new OpenPgpMessageInputStream(decrypted, options);
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
                in = new OpenPgpMessageInputStream(decrypted, options);
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
                    in = new OpenPgpMessageInputStream(decrypted, options);
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
            return bcpgIn.nextPacketTag();
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

    private PGPOnePassSignatureListWrapper readOnePassSignatures() throws IOException {
        List<Boolean> encapsulating = new ArrayList<>();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
        int tag;
        while ((tag = nextTag()) == PacketTags.ONE_PASS_SIGNATURE || tag == PacketTags.MARKER) {
            Packet packet = bcpgIn.readPacket();
            if (tag == PacketTags.ONE_PASS_SIGNATURE) {
                OnePassSignaturePacket sigPacket = (OnePassSignaturePacket) packet;
                byte[] bytes = sigPacket.getEncoded();
                encapsulating.add(bytes[bytes.length - 1] == 1);
                bcpgOut.write(bytes);
            }
        }
        bcpgOut.close();

        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(buf.toByteArray());
        PGPOnePassSignatureList signatureList = (PGPOnePassSignatureList) objectFactory.nextObject();
        return new PGPOnePassSignatureListWrapper(signatureList, encapsulating);
    }

    private PGPSignatureList readSignatures() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
        int tag = nextTag();
        while (tag == PacketTags.SIGNATURE || tag == PacketTags.MARKER) {
            Packet packet = bcpgIn.readPacket();
            if (tag == PacketTags.SIGNATURE) {
                SignaturePacket sigPacket = (SignaturePacket) packet;
                sigPacket.encode(bcpgOut);
                tag = nextTag();
            }
        }
        bcpgOut.close();

        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(buf.toByteArray());
        PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
        return signatureList;
    }

    @Override
    public int read() throws IOException {
        if (in == null) {
            automaton.assertValid();
            return -1;
        }

        int r;
        try {
            r = in.read();
        } catch (IOException e) {
            r = -1;
        }
        boolean eos = r == -1;
        if (!eos) {
            byte b = (byte) r;
            signatures.update(b);
        } else {
            in.close();
            in = null;

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

        if (in == null) {
            automaton.assertValid();
            return -1;
        }

        int r = in.read(b, off, len);
        if (r == -1) {
            in.close();
            in = null;

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

        if (in != null) {
            in.close();
            in = null;
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

    /**
     * Workaround for BC not exposing, whether an OPS is encapsulating or not.
     * TODO: Remove once our PR is merged
     *
     * @see <a href="https://github.com/bcgit/bc-java/pull/1232">PR against BC</a>
     */
    private static class PGPOnePassSignatureListWrapper {
        private final PGPOnePassSignatureList list;
        private final List<Boolean> encapsulating;

        public PGPOnePassSignatureListWrapper(PGPOnePassSignatureList signatures, List<Boolean> encapsulating) {
            this.list = signatures;
            this.encapsulating = encapsulating;
        }

        public int size() {
            return list.size();
        }
    }

    private static class Signatures {
        final ConsumerOptions options;
        List<PGPSignature> detachedSignatures = new ArrayList<>();
        List<PGPSignature> prependedSignatures = new ArrayList<>();
        List<PGPOnePassSignature> onePassSignatures = new ArrayList<>();
        List<PGPSignature> correspondingSignatures = new ArrayList<>();


        private Signatures(ConsumerOptions options) {
            this.options = options;
        }

        void addDetachedSignatures(Collection<PGPSignature> signatures) {
            for (PGPSignature signature : signatures) {
                long keyId = SignatureUtils.determineIssuerKeyId(signature);
                PGPPublicKeyRing certificate = findCertificate(keyId);
                initialize(signature, certificate, keyId);
            }
            this.detachedSignatures.addAll(signatures);
        }

        void addPrependedSignatures(PGPSignatureList signatures) {
            System.out.println("Adding " + signatures.size() + " prepended Signatures");
            for (PGPSignature signature : signatures) {
                long keyId = SignatureUtils.determineIssuerKeyId(signature);
                PGPPublicKeyRing certificate = findCertificate(keyId);
                initialize(signature, certificate, keyId);
                this.prependedSignatures.add(signature);
            }
        }

        void addOnePassSignatures(PGPOnePassSignatureListWrapper signatures) {
            System.out.println("Adding " + signatures.size() + " OPSs");
            for (PGPOnePassSignature ops : signatures.list) {
                PGPPublicKeyRing certificate = findCertificate(ops.getKeyID());
                initialize(ops, certificate);
                this.onePassSignatures.add(ops);
            }
        }

        void addOnePassCorrespondingSignatures(PGPSignatureList signatures) {
            System.out.println("Adding " + signatures.size() + " Corresponding Signatures");
            for (PGPSignature signature : signatures) {
                correspondingSignatures.add(signature);
            }
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

        private void initialize(PGPOnePassSignature ops, PGPPublicKeyRing certificate) {
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

        public void update(byte b) {
            for (PGPSignature prepended : prependedSignatures) {
                prepended.update(b);
            }
            for (PGPOnePassSignature ops : onePassSignatures) {
                ops.update(b);
            }
            for (PGPSignature detached : detachedSignatures) {
                detached.update(b);
            }
        }

        public void finish() {
            for (PGPSignature detached : detachedSignatures) {
                boolean verified = false;
                try {
                    verified = detached.verify();
                } catch (PGPException e) {
                    System.out.println(e.getMessage());
                }
                System.out.println("Detached Signature by " + Long.toHexString(detached.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
            }

            for (PGPSignature prepended : prependedSignatures) {
                boolean verified = false;
                try {
                    verified = prepended.verify();
                } catch (PGPException e) {
                    System.out.println(e.getMessage());
                }
                System.out.println("Prepended Signature by " + Long.toHexString(prepended.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
            }


            for (int i = 0; i < onePassSignatures.size(); i++) {
                PGPOnePassSignature ops = onePassSignatures.get(i);
                PGPSignature signature = correspondingSignatures.get(correspondingSignatures.size() - i - 1);
                boolean verified = false;
                try {
                    verified = ops.verify(signature);
                } catch (PGPException e) {
                    System.out.println(e.getMessage());
                }
                System.out.println("One-Pass-Signature by " + Long.toHexString(ops.getKeyID()) + " is " + (verified ? "verified" : "unverified"));
            }
        }
    }
}
