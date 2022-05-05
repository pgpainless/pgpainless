// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.bouncycastle.bcpg.PacketTags.COMPRESSED_DATA;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_1;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_2;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_3;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_4;
import static org.bouncycastle.bcpg.PacketTags.LITERAL_DATA;
import static org.bouncycastle.bcpg.PacketTags.MARKER;
import static org.bouncycastle.bcpg.PacketTags.MOD_DETECTION_CODE;
import static org.bouncycastle.bcpg.PacketTags.ONE_PASS_SIGNATURE;
import static org.bouncycastle.bcpg.PacketTags.PUBLIC_KEY;
import static org.bouncycastle.bcpg.PacketTags.PUBLIC_KEY_ENC_SESSION;
import static org.bouncycastle.bcpg.PacketTags.PUBLIC_SUBKEY;
import static org.bouncycastle.bcpg.PacketTags.RESERVED;
import static org.bouncycastle.bcpg.PacketTags.SECRET_KEY;
import static org.bouncycastle.bcpg.PacketTags.SECRET_SUBKEY;
import static org.bouncycastle.bcpg.PacketTags.SIGNATURE;
import static org.bouncycastle.bcpg.PacketTags.SYMMETRIC_KEY_ENC;
import static org.bouncycastle.bcpg.PacketTags.SYMMETRIC_KEY_ENC_SESSION;
import static org.bouncycastle.bcpg.PacketTags.SYM_ENC_INTEGRITY_PRO;
import static org.bouncycastle.bcpg.PacketTags.TRUST;
import static org.bouncycastle.bcpg.PacketTags.USER_ATTRIBUTE;
import static org.bouncycastle.bcpg.PacketTags.USER_ID;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class OpenPgpInputStream extends BufferedInputStream {

    private static final byte[] ARMOR_HEADER = "-----BEGIN PGP ".getBytes(Charset.forName("UTF8"));

    // Buffer beginning bytes of the data
    public static final int MAX_BUFFER_SIZE = 8192 * 2;

    private final byte[] buffer;
    private final int bufferLen;

    private boolean containsArmorHeader;
    private boolean containsOpenPgpPackets;
    private boolean isLikelyOpenPgpMessage;

    public OpenPgpInputStream(InputStream in, boolean check) throws IOException {
        super(in, MAX_BUFFER_SIZE);

        mark(MAX_BUFFER_SIZE);
        buffer = new byte[MAX_BUFFER_SIZE];
        bufferLen = read(buffer);
        reset();

        if (check) {
            inspectBuffer();
        }
    }

    public OpenPgpInputStream(InputStream in) throws IOException {
        this(in, true);
    }

    private void inspectBuffer() throws IOException {
        if (determineIsArmored()) {
            return;
        }

        determineIsBinaryOpenPgp();
    }

    private boolean determineIsArmored() {
        if (startsWithIgnoringWhitespace(buffer, ARMOR_HEADER, bufferLen)) {
            containsArmorHeader = true;
            return true;
        }
        return false;
    }

    /**
     * This method is still brittle.
     * Basically we try to parse OpenPGP packets from the buffer.
     * If we run into exceptions, then we know that the data is non-OpenPGP'ish.
     *
     * This breaks down though if we read plausible garbage where the data accidentally makes sense,
     * or valid, yet incomplete packets (remember, we are still only working on a portion of the data).
     */
    private void determineIsBinaryOpenPgp() throws IOException {
        if (bufferLen == -1) {
            // Empty data
            return;
        }

        ByteArrayInputStream bufferIn = new ByteArrayInputStream(buffer, 0, bufferLen);
        nonExhaustiveParseAndCheckPlausibility(bufferIn);
    }

    private void nonExhaustiveParseAndCheckPlausibility(ByteArrayInputStream bufferIn) throws IOException {
        // Read the packet header
        int hdr = bufferIn.read();
        if (hdr < 0 || (hdr & 0x80) == 0) {
            return;
        }

        boolean newPacket = (hdr & 0x40) != 0;
        int        tag = 0;
        int        bodyLen = 0;
        boolean    partial = false;

        // Determine the packet length
        if (newPacket) {
            tag = hdr & 0x3f;

            int    l = bufferIn.read();
            if (l < 192) {
                bodyLen = l;
            } else if (l <= 223) {
                int b = bufferIn.read();
                bodyLen = ((l - 192) << 8) + (b) + 192;
            } else if (l == 255) {
                bodyLen = (bufferIn.read() << 24) | (bufferIn.read() << 16) |  (bufferIn.read() << 8)  | bufferIn.read();
            } else {
                partial = true;
                bodyLen = 1 << (l & 0x1f);
            }
        } else {
            int lengthType = hdr & 0x3;
            tag = (hdr & 0x3f) >> 2;
            switch (lengthType) {
                case 0:
                    bodyLen = bufferIn.read();
                    break;
                case 1:
                    bodyLen = (bufferIn.read() << 8) | bufferIn.read();
                    break;
                case 2:
                    bodyLen = (bufferIn.read() << 24) | (bufferIn.read() << 16) | (bufferIn.read() << 8) | bufferIn.read();
                    break;
                case 3:
                    partial = true;
                    break;
                default:
                    return;
            }
        }

        // Negative body length -> garbage
        if (bodyLen < 0) {
            return;
        }

        // Try to unexhaustively parse the first packet bit by bit and check for plausibility
        BCPGInputStream bcpgIn = new BCPGInputStream(bufferIn);
        switch (tag) {
            case RESERVED:
                // How to handle this? Probably discard as garbage...
                return;

            case PUBLIC_KEY_ENC_SESSION:
                int pkeskVersion = bcpgIn.read();
                if (pkeskVersion <= 0 || pkeskVersion > 5) {
                    return;
                }

                // Skip Key-ID
                for (int i = 0; i < 8; i++) {
                    bcpgIn.read();
                }

                int pkeskAlg = bcpgIn.read();
                if (PublicKeyAlgorithm.fromId(pkeskAlg) == null) {
                    return;
                }

                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case SIGNATURE:
                int sigVersion = bcpgIn.read();
                int sigType;
                if (sigVersion == 2 || sigVersion == 3) {
                    int l = bcpgIn.read();
                    sigType = bcpgIn.read();
                } else if (sigVersion == 4 || sigVersion == 5) {
                    sigType = bcpgIn.read();
                } else {
                    return;
                }

                try {
                    SignatureType.valueOf(sigType);
                } catch (IllegalArgumentException e) {
                    return;
                }

                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case SYMMETRIC_KEY_ENC_SESSION:
                int skeskVersion = bcpgIn.read();
                if (skeskVersion == 4) {
                    int skeskAlg = bcpgIn.read();
                    if (SymmetricKeyAlgorithm.fromId(skeskAlg) == null) {
                        return;
                    }
                    // TODO: Parse S2K?
                } else {
                    return;
                }
                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case ONE_PASS_SIGNATURE:
                int opsVersion = bcpgIn.read();
                if (opsVersion == 3) {
                    int opsSigType = bcpgIn.read();
                    try {
                        SignatureType.valueOf(opsSigType);
                    } catch (IllegalArgumentException e) {
                        return;
                    }
                    int opsHashAlg = bcpgIn.read();
                    if (HashAlgorithm.fromId(opsHashAlg) == null) {
                        return;
                    }
                    int opsKeyAlg = bcpgIn.read();
                    if (PublicKeyAlgorithm.fromId(opsKeyAlg) == null) {
                        return;
                    }
                } else {
                    return;
                }

                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case SECRET_KEY:
            case PUBLIC_KEY:
            case SECRET_SUBKEY:
            case PUBLIC_SUBKEY:
                int keyVersion = bcpgIn.read();
                for (int i = 0; i < 4; i++) {
                    // Creation time
                    bcpgIn.read();
                }
                if (keyVersion == 3) {
                    long validDays = (in.read() << 8) | in.read();
                    if (validDays < 0) {
                        return;
                    }
                } else if (keyVersion == 4) {

                } else if (keyVersion == 5) {

                } else {
                    return;
                }
                int keyAlg = bcpgIn.read();
                if (PublicKeyAlgorithm.fromId(keyAlg) == null) {
                    return;
                }

                containsOpenPgpPackets = true;
                break;

            case COMPRESSED_DATA:
                int compAlg = bcpgIn.read();
                if (CompressionAlgorithm.fromId(compAlg) == null) {
                    return;
                }

                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case SYMMETRIC_KEY_ENC:
                // No data to compare :(
                containsOpenPgpPackets = true;
                break;

            case MARKER:
                byte[] marker = new byte[3];
                bcpgIn.readFully(marker);
                if (marker[0] != 0x50 || marker[1] != 0x47 || marker[2] != 0x50) {
                    return;
                }

                containsOpenPgpPackets = true;
                break;

            case LITERAL_DATA:
                int format = bcpgIn.read();
                if (StreamEncoding.fromCode(format) == null) {
                    return;
                }

                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = true;
                break;

            case TRUST:
            case USER_ID:
            case USER_ATTRIBUTE:
                // Not much to compare
                containsOpenPgpPackets = true;
                break;

            case SYM_ENC_INTEGRITY_PRO:
                int seipVersion = bcpgIn.read();
                if (seipVersion != 1) {
                    return;
                }
                isLikelyOpenPgpMessage = true;
                containsOpenPgpPackets = true;
                break;

            case MOD_DETECTION_CODE:
                byte[] digest = new byte[20];
                bcpgIn.readFully(digest);

                containsOpenPgpPackets = true;
                break;

            case EXPERIMENTAL_1:
            case EXPERIMENTAL_2:
            case EXPERIMENTAL_3:
            case EXPERIMENTAL_4:
                return;
            default:
                containsOpenPgpPackets = false;
                break;
        }
    }

    private boolean startsWithIgnoringWhitespace(byte[] bytes, byte[] subsequence, int bufferLen) {
        if (bufferLen == -1) {
            return false;
        }

        for (int i = 0; i < bufferLen; i++) {
            // Working on bytes is not trivial with unicode data, but its good enough here
            if (Character.isWhitespace(bytes[i])) {
                continue;
            }

            if ((i + subsequence.length) > bytes.length) {
                return false;
            }

            for (int j = 0; j < subsequence.length; j++) {
                if (bytes[i + j] != subsequence[j]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public boolean isAsciiArmored() {
        return containsArmorHeader;
    }

    /**
     * Return true, if the data is possibly binary OpenPGP.
     * The criterion for this are less strict than for {@link #isLikelyOpenPgpMessage()},
     * as it also accepts other OpenPGP packets at the beginning of the data stream.
     *
     * Use with caution.
     *
     * @return true if data appears to be binary OpenPGP data
     */
    public boolean isBinaryOpenPgp() {
        return containsOpenPgpPackets;
    }

    /**
     * Returns true, if the underlying data is very likely (more than 99,9%) an OpenPGP message.
     * OpenPGP Message means here that it starts with either an {@link PGPEncryptedData},
     * {@link PGPCompressedData}, {@link PGPOnePassSignature} or {@link PGPLiteralData} packet.
     * The plausability of these data packets is checked as far as possible.
     *
     * @return true if likely OpenPGP message
     */
    public boolean isLikelyOpenPgpMessage() {
        return isLikelyOpenPgpMessage;
    }

    public boolean isNonOpenPgp() {
        return !isAsciiArmored() && !isBinaryOpenPgp();
    }
}
