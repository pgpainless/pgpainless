// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.bouncycastle.bcpg.PacketTags.AEAD_ENC_DATA;
import static org.bouncycastle.bcpg.PacketTags.COMPRESSED_DATA;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_1;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_2;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_3;
import static org.bouncycastle.bcpg.PacketTags.EXPERIMENTAL_4;
import static org.bouncycastle.bcpg.PacketTags.LITERAL_DATA;
import static org.bouncycastle.bcpg.PacketTags.MARKER;
import static org.bouncycastle.bcpg.PacketTags.MOD_DETECTION_CODE;
import static org.bouncycastle.bcpg.PacketTags.ONE_PASS_SIGNATURE;
import static org.bouncycastle.bcpg.PacketTags.PADDING;
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

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.CompressedDataPacket;
import org.bouncycastle.bcpg.LiteralDataPacket;
import org.bouncycastle.bcpg.MarkerPacket;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.util.Arrays;
import org.pgpainless.algorithm.AEADAlgorithm;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

/**
 * InputStream used to determine the nature of potential OpenPGP data.
 */
public class OpenPgpInputStream extends BufferedInputStream {

    @SuppressWarnings("CharsetObjectCanBeUsed")
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
        if (checkForAsciiArmor()) {
            return;
        }

        checkForBinaryOpenPgp();
    }

    private boolean checkForAsciiArmor() {
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
     * <p>
     * This breaks down though if we read plausible garbage where the data accidentally makes sense,
     * or valid, yet incomplete packets (remember, we are still only working on a portion of the data).
     */
    private void checkForBinaryOpenPgp() throws IOException {
        if (bufferLen == -1) {
            // Empty data
            return;
        }

        ByteArrayInputStream bufferIn = new ByteArrayInputStream(buffer, 0, bufferLen);
        BCPGInputStream pIn = new BCPGInputStream(bufferIn);
        try {
            nonExhaustiveParseAndCheckPlausibility(pIn);
        } catch (IOException | UnsupportedPacketVersionException | NegativeArraySizeException e) {
            return;
        }
    }

    private void nonExhaustiveParseAndCheckPlausibility(BCPGInputStream packetIn)
            throws IOException {
        Packet packet = packetIn.readPacket();
        switch (packet.getPacketTag()) {
            case PUBLIC_KEY_ENC_SESSION:
                PublicKeyEncSessionPacket pkesk = (PublicKeyEncSessionPacket) packet;
                if (PublicKeyAlgorithm.fromId(pkesk.getAlgorithm()) == null) {
                    return;
                }
                break;

            case SIGNATURE:
                SignaturePacket sig = (SignaturePacket) packet;
                if (SignatureType.fromCode(sig.getSignatureType()) == null) {
                    return;
                }
                if (PublicKeyAlgorithm.fromId(sig.getKeyAlgorithm()) == null) {
                    return;
                }
                if (HashAlgorithm.fromId(sig.getHashAlgorithm()) == null) {
                    return;
                }
                break;

            case ONE_PASS_SIGNATURE:
                OnePassSignaturePacket ops = (OnePassSignaturePacket) packet;
                if (SignatureType.fromCode(ops.getSignatureType()) == null) {
                    return;
                }
                if (PublicKeyAlgorithm.fromId(ops.getKeyAlgorithm()) == null) {
                    return;
                }
                if (HashAlgorithm.fromId(ops.getHashAlgorithm()) == null) {
                    return;
                }
                break;

            case SYMMETRIC_KEY_ENC_SESSION:
                SymmetricKeyEncSessionPacket skesk = (SymmetricKeyEncSessionPacket) packet;
                if (SymmetricKeyAlgorithm.fromId(skesk.getEncAlgorithm()) == null) {
                    return;
                }
                break;

            case SECRET_KEY:
                SecretKeyPacket secKey = (SecretKeyPacket) packet;
                PublicKeyPacket sPubKey = secKey.getPublicKeyPacket();
                if (PublicKeyAlgorithm.fromId(sPubKey.getAlgorithm()) == null) {
                    return;
                }
                if (sPubKey.getVersion() < 3 && sPubKey.getVersion() > 6) {
                    return;
                }
                break;

            case PUBLIC_KEY:
                PublicKeyPacket pubKey = (PublicKeyPacket) packet;
                if (PublicKeyAlgorithm.fromId(pubKey.getAlgorithm()) == null) {
                    return;
                }
                if (pubKey.getVersion() < 3 && pubKey.getVersion() > 6) {
                    return;
                }
                break;

            case COMPRESSED_DATA:
                CompressedDataPacket comp = (CompressedDataPacket) packet;
                if (CompressionAlgorithm.fromId(comp.getAlgorithm()) == null) {
                    return;
                }
                break;

            case SYMMETRIC_KEY_ENC:
                // Not much we can check here
                break;

            case MARKER:
                MarkerPacket m = (MarkerPacket) packet;
                if (!Arrays.areEqual(
                        m.getEncoded(PacketFormat.CURRENT),
                        new byte[] {(byte) 0xca, 0x03, 0x50, 0x47, 0x50})) {
                    return;
                }
                break;

            case LITERAL_DATA:
                LiteralDataPacket lit = (LiteralDataPacket) packet;
                if (lit.getFormat() != 'b' &&
                        lit.getFormat() != 'u' &&
                        lit.getFormat() != 't' &&
                        lit.getFormat() != 'l' &&
                        lit.getFormat() != '1' &&
                        lit.getFormat() != 'm') {
                    return;
                }
                break;

            case SYM_ENC_INTEGRITY_PRO:
                SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) packet;
                if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1) {
                    break; // not much to check here
                }
                if (seipd.getVersion() != SymmetricEncIntegrityPacket.VERSION_2) {
                    if (SymmetricKeyAlgorithm.fromId(seipd.getCipherAlgorithm()) == null) {
                        return;
                    }
                    if (AEADAlgorithm.fromId(seipd.getAeadAlgorithm()) == null) {
                        return;
                    }
                }
                break;

            case AEAD_ENC_DATA:
                AEADEncDataPacket oed = (AEADEncDataPacket) packet;
                if (SymmetricKeyAlgorithm.fromId(oed.getAlgorithm()) == null) {
                    return;
                }
                break;

            case RESERVED:          // this Packet Type ID MUST NOT be used
            case PUBLIC_SUBKEY:     // Never found at the start of a stream
            case SECRET_SUBKEY:     // Never found at the start of a stream
            case TRUST:             // Never found at the start of a stream
            case MOD_DETECTION_CODE: // At the end of SED data - Never found at the start of a stream
            case USER_ID:           // Never found at the start of a stream
            case USER_ATTRIBUTE:    // Never found at the start of a stream
            case PADDING:           // At the end of messages (optionally padded message) or certificates
            case EXPERIMENTAL_1:    // experimental
            case EXPERIMENTAL_2:    // experimental
            case EXPERIMENTAL_3:    // experimental
            case EXPERIMENTAL_4:    // experimental
                containsOpenPgpPackets = true;
                isLikelyOpenPgpMessage = false;
                return;
            default:
                return;
        }

        containsOpenPgpPackets = true;
        if (packet.getPacketTag() != SYMMETRIC_KEY_ENC) {
            isLikelyOpenPgpMessage = true;
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
     * <p>
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
     * The plausibility of these data packets is checked as far as possible.
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
