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
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class OpenPgpMessageInputStream extends InputStream {

    protected final PDA automaton = new PDA();
    protected final ConsumerOptions options;
    protected final BCPGInputStream bcpgIn;
    protected InputStream in;

    private List<PGPSignature> signatures = new ArrayList<>();
    private List<PGPOnePassSignature> onePassSignatures = new ArrayList<>();

    public OpenPgpMessageInputStream(InputStream inputStream, ConsumerOptions options)
            throws IOException, PGPException {
        this.options = options;
        // TODO: Use BCPGInputStream.wrap(inputStream);
        if (inputStream instanceof BCPGInputStream) {
            this.bcpgIn = (BCPGInputStream) inputStream;
        } else {
            this.bcpgIn = new BCPGInputStream(inputStream);
        }

        walk();
    }

    private void walk() throws IOException, PGPException {
        loop: while (true) {

            int tag = bcpgIn.nextPacketTag();
            if (tag == -1) {
                break loop;
            }

            OpenPgpPacket nextPacket = OpenPgpPacket.requireFromTag(tag);
            switch (nextPacket) {
                case LIT:
                    automaton.next(InputAlphabet.LiteralData);
                    PGPLiteralData literalData = new PGPLiteralData(bcpgIn);
                    in = literalData.getDataStream();
                    break loop;

                case COMP:
                    automaton.next(InputAlphabet.CompressedData);
                    PGPCompressedData compressedData = new PGPCompressedData(bcpgIn);
                    in = new OpenPgpMessageInputStream(compressedData.getDataStream(), options);
                    break loop;

                case OPS:
                    automaton.next(InputAlphabet.OnePassSignatures);
                    readOnePassSignatures();
                    break;

                case SIG:
                    automaton.next(InputAlphabet.Signatures);
                    readSignatures();
                    break;

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

                case SK:
                case PK:
                case SSK:
                case PSK:
                case TRUST:
                case UID:
                case UATTR:

                case MOD:
                    break;

                case EXP_1:
                case EXP_2:
                case EXP_3:
                case EXP_4:
                    break;
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

    private void readOnePassSignatures() throws IOException {
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
        for (PGPOnePassSignature ops : signatureList) {
            onePassSignatures.add(ops);
        }
    }

    private void readSignatures() throws IOException {
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
        for (PGPSignature signature : signatureList) {
            signatures.add(signature);
        }
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
        if (r == -1) {
            if (in instanceof OpenPgpMessageInputStream) {
                System.out.println("Read -1: close " + automaton);
                in.close();
                in = null;
            } else {
                try {
                    System.out.println("Walk " + automaton);
                    walk();
                } catch (PGPException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return r;
    }

    @Override
    public void close() throws IOException {
        if (in == null) {
            System.out.println("Close " + automaton);
            automaton.next(InputAlphabet.EndOfSequence);
            automaton.assertValid();
            return;
        }
        try {
            in.close();
            in = null;
            // Nested streams (except LiteralData) need to be closed.
            if (automaton.getState() != PDA.State.LiteralMessage) {
                automaton.next(InputAlphabet.EndOfSequence);
                automaton.assertValid();
            }
        } catch (IOException e) {
            //
        }

        super.close();
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
}
