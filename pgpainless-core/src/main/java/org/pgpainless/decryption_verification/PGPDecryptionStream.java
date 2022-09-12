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
import org.bouncycastle.bcpg.SymmetricEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.algorithm.OpenPgpPacket;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.implementation.ImplementationFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.NoSuchElementException;
import java.util.Stack;

public class PGPDecryptionStream extends InputStream {

    PushdownAutomaton automaton = new PushdownAutomaton();
    // nested streams, outermost at the bottom of the stack
    Stack<Layer> packetLayers = new Stack<>();

    public PGPDecryptionStream(InputStream inputStream) throws IOException, PGPException {
        try {
            packetLayers.push(Layer.initial(inputStream));
            walkLayer();
        } catch (MalformedOpenPgpMessageException e) {
            throw e.toRuntimeException();
        }
    }

    private void walkLayer() throws PGPException, IOException {
        if (packetLayers.isEmpty()) {
            return;
        }

        Layer layer = packetLayers.peek();
        BCPGInputStream inputStream = (BCPGInputStream) layer.inputStream;

        loop: while (true) {
            if (inputStream.nextPacketTag() == -1) {
                popLayer();
                break loop;
            }
            OpenPgpPacket tag = nextTagOrThrow(inputStream);
            switch (tag) {

                case PKESK:
                    PublicKeyEncSessionPacket pkeskPacket = (PublicKeyEncSessionPacket) inputStream.readPacket();
                    PGPEncryptedDataList encList = null;
                    break;
                case SIG:
                    automaton.next(PushdownAutomaton.InputAlphabet.Signatures);

                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    BCPGOutputStream bcpgOut = new BCPGOutputStream(buf);
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
                case SKESK:
                    SymmetricKeyEncSessionPacket skeskPacket = (SymmetricKeyEncSessionPacket) inputStream.readPacket();

                    break;
                case OPS:
                    automaton.next(PushdownAutomaton.InputAlphabet.OnePassSignatures);
                    buf = new ByteArrayOutputStream();
                    bcpgOut = new BCPGOutputStream(buf);
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
                case SK:
                    break;
                case PK:
                    break;
                case SSK:
                    break;
                case COMP:
                    automaton.next(PushdownAutomaton.InputAlphabet.CompressedData);
                    PGPCompressedData compressedData = new PGPCompressedData(inputStream);
                    inputStream = new BCPGInputStream(compressedData.getDataStream());
                    packetLayers.push(Layer.CompressedData(inputStream));
                    break;
                case SED:
                    automaton.next(PushdownAutomaton.InputAlphabet.EncryptedData);
                    SymmetricEncDataPacket symmetricEncDataPacket = (SymmetricEncDataPacket) inputStream.readPacket();
                    break;
                case MARKER:
                    inputStream.readPacket(); // discard
                    break;
                case LIT:
                    automaton.next(PushdownAutomaton.InputAlphabet.LiteralData);
                    PGPLiteralData literalData = new PGPLiteralData(inputStream);
                    packetLayers.push(Layer.LiteralMessage(literalData.getDataStream()));
                    break loop;
                case TRUST:
                    TrustPacket trustPacket = (TrustPacket) inputStream.readPacket();
                    break;
                case UID:
                    UserIDPacket userIDPacket = (UserIDPacket) inputStream.readPacket();
                    break;
                case PSK:
                    break;
                case UATTR:
                    UserAttributePacket userAttributePacket = (UserAttributePacket) inputStream.readPacket();
                    break;
                case SEIPD:
                    automaton.next(PushdownAutomaton.InputAlphabet.EncryptedData);
                    SymmetricEncIntegrityPacket symmetricEncIntegrityPacket = (SymmetricEncIntegrityPacket) inputStream.readPacket();
                    break;
                case MOD:
                    ModDetectionCodePacket modDetectionCodePacket = (ModDetectionCodePacket) inputStream.readPacket();
                    break;
                case EXP_1:
                    break;
                case EXP_2:
                    break;
                case EXP_3:
                    break;
                case EXP_4:
                    break;
            }
        }
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
            automaton.next(PushdownAutomaton.InputAlphabet.EndOfSequence);
    }

    @Override
    public int read() throws IOException {
        if (packetLayers.isEmpty()) {
            try {
                automaton.assertValid();
            } catch (MalformedOpenPgpMessageException e) {
                throw e.toRuntimeException();
            }
            return -1;
        }

        int r = -1;
        try {
            r = packetLayers.peek().inputStream.read();
        } catch (IOException e) {
        }
        if (r == -1) {
            try {
                popLayer();
                walkLayer();
            } catch (MalformedOpenPgpMessageException e) {
                throw e.toRuntimeException();
            }
            catch (PGPException e) {
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

        static Layer LiteralMessage(InputStream inputStream) {
            return new Layer(inputStream, false);
        }

        static Layer CompressedData(InputStream inputStream) {
            return new Layer(inputStream, true);
        }
    }
}
