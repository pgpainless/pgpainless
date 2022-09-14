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
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.OpenPgpPacket;
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
import org.pgpainless.signature.consumer.DetachedSignatureCheck;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class OpenPgpMessageInputStream extends InputStream {

    protected final PDA automaton = new PDA();
    protected final ConsumerOptions options;
    protected final BCPGInputStream bcpgIn;
    protected InputStream in;

    private boolean closed = false;

    private Signatures signatures = new Signatures();

    public OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options)
            throws IOException, PGPException {
        // TODO: Use BCPGInputStream.wrap(inputStream);
        if (inputStream instanceof BCPGInputStream) {
            this.bcpgIn = (BCPGInputStream) inputStream;
        } else {
            this.bcpgIn = new BCPGInputStream(inputStream);
        }

        this.options = options;
        this.signatures.addDetachedSignatures(options.getDetachedSignatures());

        consumePackets();
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
        int tag;
        loop: while ((tag = bcpgIn.nextPacketTag()) != -1) {
            OpenPgpPacket nextPacket = OpenPgpPacket.requireFromTag(tag);
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
                    in = new OpenPgpMessageInputStream(compressedData.getDataStream(), options);
                    break loop;

                // One Pass Signatures
                case OPS:
                    automaton.next(InputAlphabet.OnePassSignatures);
                    signatures.addOnePassSignatures(readOnePassSignatures());
                    break;

                // Signatures - either prepended to the message, or corresponding to the One Pass Signatures
                case SIG:
                    automaton.next(InputAlphabet.Signatures);
                    PGPSignatureList signatureList = readSignatures();
                    if (automaton.peekStack() == StackAlphabet.ops) {
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
                    PGPEncryptedDataList encDataList = new PGPEncryptedDataList(bcpgIn);

                    // TODO: Replace with !encDataList.isIntegrityProtected()
                    if (!encDataList.get(0).isIntegrityProtected()) {
                        throw new MessageNotIntegrityProtectedException();
                    }

                    SortedESKs esks = new SortedESKs(encDataList);

                    if (options.getSessionKey() != null) {
                        SessionKeyDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                                .getSessionKeyDataDecryptorFactory(options.getSessionKey());
                        // TODO: Replace with encDataList.addSessionKeyDecryptionMethod(sessionKey)
                        PGPEncryptedData esk = esks.all().get(0);
                        try {
                            if (esk instanceof PGPPBEEncryptedData) {
                                PGPPBEEncryptedData skesk = (PGPPBEEncryptedData) esk;
                                in = skesk.getDataStream(decryptorFactory);
                                break loop;
                            } else if (esk instanceof PGPPublicKeyEncryptedData) {
                                PGPPublicKeyEncryptedData pkesk = (PGPPublicKeyEncryptedData) esk;
                                in = pkesk.getDataStream(decryptorFactory);
                                break loop;
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
                                break loop;
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
                            break loop;
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
                                break loop;
                            } catch (PGPException e) {
                                // hm :/
                            }
                        }
                    }

                    // TODO: try interactive password callbacks

                    throw new MissingDecryptionMethodException("No working decryption method found.");

                case MARKER:
                    bcpgIn.readPacket(); // skip marker packet
                    break;

                // Key Packets are illegal in this context
                case SK:
                case PK:
                case SSK:
                case PSK:
                case TRUST:
                case UID:
                case UATTR:

                case MOD:
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

    private PGPOnePassSignatureList readOnePassSignatures() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
        int tag = bcpgIn.nextPacketTag();
        while (tag == PacketTags.ONE_PASS_SIGNATURE || tag == PacketTags.MARKER) {
            Packet packet = bcpgIn.readPacket();
            if (tag == PacketTags.ONE_PASS_SIGNATURE) {
                OnePassSignaturePacket sigPacket = (OnePassSignaturePacket) packet;
                sigPacket.encode(bcpgOut);
            }
        }
        bcpgOut.close();

        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(buf.toByteArray());
        PGPOnePassSignatureList signatureList = (PGPOnePassSignatureList) objectFactory.nextObject();
        return signatureList;
    }

    private PGPSignatureList readSignatures() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
        int tag = bcpgIn.nextPacketTag();
        while (tag == PacketTags.SIGNATURE || tag == PacketTags.MARKER) {
            Packet packet = bcpgIn.readPacket();
            if (tag == PacketTags.SIGNATURE) {
                SignaturePacket sigPacket = (SignaturePacket) packet;
                sigPacket.encode(bcpgOut);
                tag = bcpgIn.nextPacketTag();
            }
        }
        bcpgOut.close();

        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(buf.toByteArray());
        PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
        return signatureList;
    }

    @Override
    public int read() throws IOException {
        int r = -1;
        if (in != null) {
            try {
                r = in.read();
            } catch (IOException e) {
                //
            }
        }
        if (r != -1) {
            byte b = (byte) r;
            signatures.update(b);
        } else {
            if (in instanceof OpenPgpMessageInputStream) {
                in.close();
                in = null;
            } else {
                try {
                    System.out.println("Walk " + automaton);
                    consumePackets();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return r;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        if (in != null) {
            in.close();
            in = null;
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

    private static class Signatures {
        List<PGPSignature> detachedSignatures = new ArrayList<>();
        List<PGPSignature> prependedSignatures = new ArrayList<>();
        List<PGPOnePassSignature> onePassSignatures = new ArrayList<>();
        List<PGPSignature> correspondingSignatures = new ArrayList<>();

        void addDetachedSignatures(Collection<PGPSignature> signatures) {
            this.detachedSignatures.addAll(signatures);
        }

        void addPrependedSignatures(PGPSignatureList signatures) {
            for (PGPSignature signature : signatures) {
                this.prependedSignatures.add(signature);
            }
        }

        void addOnePassSignatures(PGPOnePassSignatureList signatures) {
            for (PGPOnePassSignature ops : signatures) {
                this.onePassSignatures.add(ops);
            }
        }

        void addOnePassCorrespondingSignatures(PGPSignatureList signatures) {
            for (PGPSignature signature : signatures) {
                correspondingSignatures.add(signature);
            }
        }

        public void update(byte b) {
            /**
            for (PGPSignature prepended : prependedSignatures) {
                prepended.update(b);
            }
            for (PGPOnePassSignature ops : onePassSignatures) {
                ops.update(b);
            }
            for (PGPSignature detached : detachedSignatures) {
                detached.update(b);
            }
             */
        }

        public void finish() {
            for (PGPSignature detached : detachedSignatures) {

            }
        }
    }
}
