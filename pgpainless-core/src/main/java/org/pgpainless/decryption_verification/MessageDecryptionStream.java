// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ModDetectionCodePacket;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.pgpainless.algorithm.OpenPgpPacket;
import org.pgpainless.decryption_verification.automaton.InputAlphabet;
import org.pgpainless.decryption_verification.automaton.NestingPDA;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Stack;

public class MessageDecryptionStream extends InputStream {

    private final ConsumerOptions options;

    NestingPDA automaton = new NestingPDA();
    // nested streams, outermost at the bottom of the stack
    Stack<Layer> packetLayers = new Stack<>();
    List<PublicKeyEncSessionPacket> pkeskList = new ArrayList<>();
    List<SymmetricKeyEncSessionPacket> skeskList = new ArrayList<>();

    public MessageDecryptionStream(InputStream inputStream, ConsumerOptions options)
            throws IOException, PGPException {
        this.options = options;
        packetLayers.push(Layer.initial(inputStream));
        walkLayer();
    }

    private void walkLayer() throws PGPException, IOException {
        if (packetLayers.isEmpty()) {
            return;
        }

        // We are currently in the deepest layer
        Layer layer = packetLayers.peek();
        BCPGInputStream inputStream = (BCPGInputStream) layer.inputStream;

        loop: while (true) {
            if (inputStream.nextPacketTag() == -1) {
                popLayer();
                break loop;
            }
            OpenPgpPacket tag = nextTagOrThrow(inputStream);
            switch (tag) {

                case LIT:
                    automaton.next(InputAlphabet.LiteralData);
                    PGPLiteralData literalData = new PGPLiteralData(inputStream);
                    packetLayers.push(Layer.literalMessage(literalData.getDataStream()));
                    break loop;

                case COMP:
                    automaton.next(InputAlphabet.CompressedData);
                    PGPCompressedData compressedData = new PGPCompressedData(inputStream);
                    inputStream = new BCPGInputStream(compressedData.getDataStream());
                    packetLayers.push(Layer.compressedData(inputStream));
                    break;

                case OPS:
                    automaton.next(InputAlphabet.OnePassSignatures);
                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
                    while (inputStream.nextPacketTag() == PacketTags.ONE_PASS_SIGNATURE || inputStream.nextPacketTag() == PacketTags.MARKER) {
                        Packet packet = inputStream.readPacket();
                        if (packet instanceof OnePassSignaturePacket) {
                            OnePassSignaturePacket sig = (OnePassSignaturePacket) packet;
                            sig.encode(bcpgOut);
                        }
                    }
                    PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) ImplementationFactory.getInstance()
                            .getPGPObjectFactory(buf.toByteArray()).nextObject();
                    break;

                case SIG:
                    automaton.next(InputAlphabet.Signatures);

                    buf = new ByteArrayOutputStream();
                    bcpgOut = new BCPGOutputStream(buf);
                    while (inputStream.nextPacketTag() == PacketTags.SIGNATURE || inputStream.nextPacketTag() == PacketTags.MARKER) {
                        Packet packet = inputStream.readPacket();
                        if (packet instanceof SignaturePacket) {
                            SignaturePacket sig = (SignaturePacket) packet;
                            sig.encode(bcpgOut);
                        }
                    }
                    PGPSignatureList signatures = (PGPSignatureList) ImplementationFactory.getInstance()
                            .getPGPObjectFactory(buf.toByteArray()).nextObject();
                    break;

                case PKESK:
                    PublicKeyEncSessionPacket pkeskPacket = (PublicKeyEncSessionPacket) inputStream.readPacket();
                    pkeskList.add(pkeskPacket);
                    break;

                case SKESK:
                    SymmetricKeyEncSessionPacket skeskPacket = (SymmetricKeyEncSessionPacket) inputStream.readPacket();
                    skeskList.add(skeskPacket);
                    break;

                case SED:
                    if (!options.isIgnoreMDCErrors()) {
                        throw new MessageNotIntegrityProtectedException();
                    }
                    // No break; we continue below!
                case SEIPD:
                    automaton.next(InputAlphabet.EncryptedData);
                    PGPEncryptedDataList encryptedDataList = assembleEncryptedDataList(inputStream);

                    for (PGPEncryptedData encData : encryptedDataList) {
                        if (encData instanceof PGPPBEEncryptedData) {
                            PGPPBEEncryptedData skenc = (PGPPBEEncryptedData) encData;
                            for (Passphrase passphrase : options.getDecryptionPassphrases()) {
                                PBEDataDecryptorFactory decryptorFactory = ImplementationFactory.getInstance()
                                        .getPBEDataDecryptorFactory(passphrase);
                                InputStream decryptedIn = skenc.getDataStream(decryptorFactory);
                                packetLayers.push(Layer.encryptedData(new BCPGInputStream(decryptedIn)));
                                walkLayer();
                                break loop;
                            }
                        }
                    }
                    throw new MissingDecryptionMethodException("Cannot decrypt message.");

                case MARKER:
                    inputStream.readPacket(); // discard
                    break;

                case SK:
                case PK:
                case SSK:
                case PSK:
                case TRUST:
                case UID:
                case UATTR:
                    throw new MalformedOpenPgpMessageException("OpenPGP packet " + tag + " MUST NOT be part of OpenPGP messages.");
                case MOD:
                    ModDetectionCodePacket modDetectionCodePacket = (ModDetectionCodePacket) inputStream.readPacket();
                    break;
                case EXP_1:
                case EXP_2:
                case EXP_3:
                case EXP_4:
                    throw new MalformedOpenPgpMessageException("Experimental packet " + tag + " found inside the message.");
            }
        }
    }

    private PGPEncryptedDataList assembleEncryptedDataList(BCPGInputStream inputStream)
            throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);

        for (SymmetricKeyEncSessionPacket skesk : skeskList) {
            bcpgOut.write(skesk.getEncoded());
        }
        skeskList.clear();
        for (PublicKeyEncSessionPacket pkesk : pkeskList) {
            bcpgOut.write(pkesk.getEncoded());
        }
        pkeskList.clear();

        SequenceInputStream sqin = new SequenceInputStream(
                new ByteArrayInputStream(buf.toByteArray()), inputStream);

        PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) ImplementationFactory.getInstance()
                .getPGPObjectFactory(sqin).nextObject();
        return encryptedDataList;
    }

    private OpenPgpPacket nextTagOrThrow(BCPGInputStream inputStream)
            throws IOException, InvalidOpenPgpPacketException {
        try {
            return OpenPgpPacket.requireFromTag(inputStream.nextPacketTag());
        } catch (NoSuchElementException e) {
            throw new InvalidOpenPgpPacketException(e.getMessage());
        }
    }

    private void popLayer() throws MalformedOpenPgpMessageException {
        if (packetLayers.pop().isNested)
            automaton.next(InputAlphabet.EndOfSequence);
    }

    @Override
    public int read() throws IOException {
        if (packetLayers.isEmpty()) {
            automaton.assertValid();
            return -1;
        }

        int r = -1;
        try {
            r = packetLayers.peek().inputStream.read();
        } catch (IOException e) {
        }
        if (r == -1) {
            popLayer();
            try {
                walkLayer();
            } catch (PGPException e) {
                throw new RuntimeException(e);
            }
            return read();
        }
        return r;
    }

    public static class InvalidOpenPgpPacketException extends PGPException {

        public InvalidOpenPgpPacketException(String message) {
            super(message);
        }
    }

    private static class Layer {
        InputStream inputStream;
        boolean isNested;

        private Layer(InputStream inputStream, boolean isNested) {
            this.inputStream = inputStream;
            this.isNested = isNested;
        }

        static Layer initial(InputStream inputStream) {
            BCPGInputStream bcpgIn;
            if (inputStream instanceof BCPGInputStream) {
                bcpgIn = (BCPGInputStream) inputStream;
            } else {
                bcpgIn = new BCPGInputStream(inputStream);
            }
            return new Layer(bcpgIn, true);
        }

        static Layer literalMessage(InputStream inputStream) {
            return new Layer(inputStream, false);
        }

        static Layer compressedData(InputStream inputStream) {
            return new Layer(inputStream, true);
        }

        static Layer encryptedData(InputStream inputStream) {
            return new Layer(inputStream, true);
        }
    }
}
