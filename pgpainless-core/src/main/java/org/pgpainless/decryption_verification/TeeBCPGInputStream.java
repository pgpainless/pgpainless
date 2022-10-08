// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.MarkerPacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.OpenPgpPacket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.NoSuchElementException;

/**
 * Since we need to update signatures with data from the underlying stream, this class is used to tee out the data.
 * Unfortunately we cannot simply override {@link BCPGInputStream#read()} to tee the data out though, since
 * {@link BCPGInputStream#readPacket()} inconsistently calls a mix of {@link BCPGInputStream#read()} and
 * {@link InputStream#read()} of the underlying stream. This would cause the second length byte to get swallowed up.
 *
 * Therefore, this class delegates the teeing to an {@link DelayedTeeInputStreamInputStream} which wraps the underlying
 * stream. Since calling {@link BCPGInputStream#nextPacketTag()} reads up to and including the next packets tag,
 * we need to delay teeing out that byte to signature verifiers.
 * Hence, the reading methods of the {@link TeeBCPGInputStream} handle pushing this byte to the output stream using
 * {@link DelayedTeeInputStreamInputStream#squeeze()}.
 */
public class TeeBCPGInputStream {

    protected final DelayedTeeInputStreamInputStream delayedTee;
    // InputStream of OpenPGP packets of the current layer
    protected final BCPGInputStream packetInputStream;

    public TeeBCPGInputStream(BCPGInputStream inputStream, OutputStream outputStream) {
        this.delayedTee = new DelayedTeeInputStreamInputStream(inputStream, outputStream);
        this.packetInputStream = BCPGInputStream.wrap(delayedTee);
    }

    public OpenPgpPacket nextPacketTag() throws IOException {
        int tag = packetInputStream.nextPacketTag();
        if (tag == -1) {
            return null;
        }

        OpenPgpPacket packet;
        try {
            packet = OpenPgpPacket.requireFromTag(tag);
        } catch (NoSuchElementException e) {
            throw e;
        }
        return packet;
    }

    public Packet readPacket() throws IOException {
        return packetInputStream.readPacket();
    }

    public PGPCompressedData readCompressedData() throws IOException {
        delayedTee.squeeze();
        PGPCompressedData compressedData = new PGPCompressedData(packetInputStream);
        return compressedData;
    }

    public PGPLiteralData readLiteralData() throws IOException {
        delayedTee.squeeze();
        return new PGPLiteralData(packetInputStream);
    }

    public PGPEncryptedDataList readEncryptedDataList() throws IOException {
        delayedTee.squeeze();
        return new PGPEncryptedDataList(packetInputStream);
    }

    public PGPOnePassSignature readOnePassSignature() throws PGPException, IOException {
        PGPOnePassSignature onePassSignature = new PGPOnePassSignature(packetInputStream);
        delayedTee.squeeze();
        return onePassSignature;
    }

    public PGPSignature readSignature() throws PGPException, IOException {
        PGPSignature signature = new PGPSignature(packetInputStream);
        delayedTee.squeeze();
        return signature;
    }

    public MarkerPacket readMarker() throws IOException {
        MarkerPacket markerPacket = (MarkerPacket) readPacket();
        delayedTee.squeeze();
        return markerPacket;
    }

    public static class DelayedTeeInputStreamInputStream extends InputStream {

        private int last = -1;
        private final InputStream inputStream;
        private final OutputStream outputStream;

        public DelayedTeeInputStreamInputStream(InputStream inputStream, OutputStream outputStream) {
            this.inputStream = inputStream;
            this.outputStream = outputStream;
        }

        @Override
        public int read() throws IOException {
            if (last != -1) {
                outputStream.write(last);
            }
            last = inputStream.read();
            return last;
        }

        /**
         * Squeeze the last byte out and update the output stream.
         *
         * @throws IOException in case of an IO error
         */
        public void squeeze() throws IOException {
            if (last != -1) {
                outputStream.write(last);
            }
            last = -1;
        }
    }
}
