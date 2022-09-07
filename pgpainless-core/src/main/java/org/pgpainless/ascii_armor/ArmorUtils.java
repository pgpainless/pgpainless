// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.ascii_armor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpInputStream;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Tuple;

public final class ArmorUtils {

    // MessageIDs are 32 printable characters
    private static final Pattern PATTERN_MESSAGE_ID = Pattern.compile("^\\S{32}$");

    public static final String HEADER_COMMENT = "Comment";
    public static final String HEADER_VERSION = "Version";
    public static final String HEADER_MESSAGEID = "MessageID";
    public static final String HEADER_HASH = "Hash";
    public static final String HEADER_CHARSET = "Charset";

    private ArmorUtils() {

    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPSecretKey}.
     *
     * @param secretKey secret key
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPSecretKey secretKey)
            throws IOException {
        MultiMap<String, String> header = keyToHeader(secretKey.getPublicKey());
        return toAsciiArmoredString(secretKey.getEncoded(), header);
    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPPublicKey}.
     *
     * @param publicKey public key
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPPublicKey publicKey)
            throws IOException {
        MultiMap<String, String> header = keyToHeader(publicKey);
        return toAsciiArmoredString(publicKey.getEncoded(), header);
    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPSecretKeyRing}.
     *
     * @param secretKeys secret key ring
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPSecretKeyRing secretKeys)
            throws IOException {
        MultiMap<String, String> header = keysToHeader(secretKeys);
        return toAsciiArmoredString(secretKeys.getEncoded(), header);
    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPPublicKeyRing}.
     *
     * @param publicKeys public key ring
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPPublicKeyRing publicKeys)
            throws IOException {
        MultiMap<String, String> header = keysToHeader(publicKeys);
        return toAsciiArmoredString(publicKeys.getEncoded(), header);
    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPSecretKeyRingCollection}.
     * The encoding will use per-key ASCII armors protecting each {@link PGPSecretKeyRing} individually.
     * Those armors are then concatenated with newlines in between.
     *
     * @param secretKeyRings secret key ring collection
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPSecretKeyRingCollection secretKeyRings)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Iterator<PGPSecretKeyRing> iterator = secretKeyRings.iterator(); iterator.hasNext(); ) {
            PGPSecretKeyRing secretKeyRing = iterator.next();
            sb.append(toAsciiArmoredString(secretKeyRing));
            if (iterator.hasNext()) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Return the ASCII armored encoding of the given {@link PGPPublicKeyRingCollection}.
     * The encoding will use per-key ASCII armors protecting each {@link PGPPublicKeyRing} individually.
     * Those armors are then concatenated with newlines in between.
     *
     * @param publicKeyRings public key ring collection
     * @return ascii armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull PGPPublicKeyRingCollection publicKeyRings)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Iterator<PGPPublicKeyRing> iterator = publicKeyRings.iterator(); iterator.hasNext(); ) {
            PGPPublicKeyRing publicKeyRing = iterator.next();
            sb.append(toAsciiArmoredString(publicKeyRing));
            if (iterator.hasNext()) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * Return the ASCII armored encoding of the given OpenPGP data bytes.
     *
     * @param bytes openpgp data
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull byte[] bytes)
            throws IOException {
        return toAsciiArmoredString(bytes, null);
    }

    /**
     * Return the ASCII armored encoding of the given OpenPGP data bytes.
     * The ASCII armor will include headers from the header map.
     *
     * @param bytes OpenPGP data
     * @param additionalHeaderValues header map
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull byte[] bytes,
                                              @Nullable MultiMap<String, String> additionalHeaderValues)
            throws IOException {
        return toAsciiArmoredString(new ByteArrayInputStream(bytes), additionalHeaderValues);
    }

    /**
     * Return the ASCII armored encoding of the {@link InputStream} containing OpenPGP data.
     *
     * @param inputStream input stream of OpenPGP data
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull InputStream inputStream)
            throws IOException {
        return toAsciiArmoredString(inputStream, null);
    }

    /**
     * Return the ASCII armored encoding of the OpenPGP data from the given {@link InputStream}.
     * The ASCII armor will include armor headers from the given header map.
     *
     * @param inputStream input stream of OpenPGP data
     * @param additionalHeaderValues ASCII armor header map
     * @return ASCII armored encoding
     *
     * @throws IOException in case of an io error
     */
    @Nonnull
    public static String toAsciiArmoredString(@Nonnull InputStream inputStream,
                                              @Nullable MultiMap<String, String> additionalHeaderValues)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = toAsciiArmoredStream(out, additionalHeaderValues);
        Streams.pipeAll(inputStream, armor);
        armor.close();

        return out.toString();
    }

    /**
     * Return an {@link ArmoredOutputStream} prepared with headers for the given key ring, which wraps the given
     * {@link OutputStream}.
     *
     * The armored output stream can be used to encode the key ring by calling {@link PGPKeyRing#encode(OutputStream)}
     * with the armored output stream as an argument.
     *
     * @param keyRing key ring
     * @param outputStream wrapped output stream
     * @return armored output stream
     */
    @Nonnull
    public static ArmoredOutputStream toAsciiArmoredStream(@Nonnull PGPKeyRing keyRing,
                                                           @Nonnull OutputStream outputStream) {
        MultiMap<String, String> header = keysToHeader(keyRing);
        return toAsciiArmoredStream(outputStream, header);
    }

    /**
     * Create an {@link ArmoredOutputStream} wrapping the given {@link OutputStream}.
     * The armored output stream will be prepared with armor headers given by header.
     *
     * Note: Since the armored output stream is retrieved from {@link ArmoredOutputStreamFactory#get(OutputStream)},
     * it may already come with custom headers. Hence, the header entries given by header are appended below those
     * already populated headers.
     *
     * @param outputStream output stream to wrap
     * @param header map of header entries
     * @return armored output stream
     */
    @Nonnull
    public static ArmoredOutputStream toAsciiArmoredStream(@Nonnull OutputStream outputStream,
                                                           @Nullable MultiMap<String, String> header) {
        ArmoredOutputStream armoredOutputStream = ArmoredOutputStreamFactory.get(outputStream);
        if (header != null) {
            for (String headerKey : header.keySet()) {
                for (String headerValue : header.get(headerKey)) {
                    armoredOutputStream.addHeader(headerKey, headerValue);
                }
            }
        }
        return armoredOutputStream;
    }

    /**
     * Generate a header map for ASCII armor from the given {@link PGPKeyRing}.
     *
     * @param keyRing key ring
     * @return header map
     */
    @Nonnull
    private static MultiMap<String, String> keysToHeader(@Nonnull PGPKeyRing keyRing) {
        PGPPublicKey publicKey = keyRing.getPublicKey();
        return keyToHeader(publicKey);
    }

    /**
     * Generate a header map for ASCII armor from the given {@link PGPPublicKey}.
     * The header map consists of a comment field of the keys pretty-printed fingerprint,
     * as well as some optional user-id information (see {@link #setUserIdInfoOnHeader(MultiMap, PGPPublicKey)}.
     *
     * @param publicKey public key
     * @return header map
     */
    @Nonnull
    private static MultiMap<String, String> keyToHeader(@Nonnull PGPPublicKey publicKey) {
        MultiMap<String, String> header = new MultiMap<>();
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(publicKey);

        header.put(HEADER_COMMENT, fingerprint.prettyPrint());
        setUserIdInfoOnHeader(header, publicKey);
        return header;
    }

    /**
     * Add user-id information to the header map.
     * If the key is carrying at least one user-id, we add a comment for the probable primary user-id.
     * If the key carries more than one user-id, we further add a comment stating how many further identities
     * the key has.
     *
     * @param header header map
     * @param publicKey public key
     */
    private static void setUserIdInfoOnHeader(@Nonnull MultiMap<String, String> header,
                                              @Nonnull PGPPublicKey publicKey) {
        Tuple<String, Integer> idCount = getPrimaryUserIdAndUserIdCount(publicKey);
        String primary = idCount.getA();
        int totalCount = idCount.getB();
        if (primary != null) {
            header.put(HEADER_COMMENT, primary);
        }
        if (totalCount == 2) {
            header.put(HEADER_COMMENT, "1 further identity");
        } else if (totalCount > 2) {
            header.put(HEADER_COMMENT, String.format("%d further identities", totalCount - 1));
        }
    }

    /**
     * Determine a probable primary user-id, as well as the total number of user-ids on the given {@link PGPPublicKey}.
     * This method is trimmed for efficiency and does not do any cryptographic validation of signatures.
     *
     * The key might not have any user-id at all, in which case {@link Tuple#getA()} will return null.
     * The key might have some user-ids, but none of it marked as primary, in which case {@link Tuple#getA()}
     * will return the first user-id of the key.
     *
     * @param publicKey public key
     * @return tuple consisting of a primary user-id candidate, and the total number of user-ids on the key.
     */
    @Nonnull
    private static Tuple<String, Integer> getPrimaryUserIdAndUserIdCount(@Nonnull PGPPublicKey publicKey) {
        // Quickly determine the primary user-id + number of total user-ids
        // NOTE: THIS METHOD DOES NOT CRYPTOGRAPHICALLY VERIFY THE SIGNATURES
        // DO NOT RELY ON IT!
        Iterator<String> userIds = publicKey.getUserIDs();
        int countIdentities = 0;
        String first = null;
        String primary = null;
        while (userIds.hasNext()) {
            countIdentities++;
            String userId = userIds.next();
            // remember the first user-id
            if (first == null) {
                first = userId;
            }

            if (primary == null) {
                Iterator<PGPSignature> signatures = publicKey.getSignaturesForID(userId);
                while (signatures.hasNext()) {
                    PGPSignature signature = signatures.next();
                    if (signature.getHashedSubPackets().isPrimaryUserID()) {
                        primary = userId;
                        break;
                    }
                }
            }
        }
        // It may happen that no user-id is marked as primary
        // in that case print the first one
        String printed = primary != null ? primary : first;
        return new Tuple<>(printed, countIdentities);
    }

    /**
     * Add an ASCII armor header entry about the used hash algorithm into the {@link ArmoredOutputStream}.
     *
     * @param armor armored output stream
     * @param hashAlgorithm hash algorithm
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2">
     *     RFC 4880 - OpenPGP Message Format §6.2. Forming ASCII Armor</a>
     */
    public static void addHashAlgorithmHeader(@Nonnull ArmoredOutputStream armor,
                                              @Nonnull HashAlgorithm hashAlgorithm) {
        armor.addHeader(HEADER_HASH, hashAlgorithm.getAlgorithmName());
    }

    /**
     * Add an ASCII armor comment header entry into the {@link ArmoredOutputStream}.
     *
     * @param armor armored output stream
     * @param comment free-text comment
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2">
     *     RFC 4880 - OpenPGP Message Format §6.2. Forming ASCII Armor</a>
     */
    public static void addCommentHeader(@Nonnull ArmoredOutputStream armor,
                                        @Nonnull String comment) {
        armor.addHeader(HEADER_COMMENT, comment);
    }

    /**
     * Add an ASCII armor message-id header entry into the {@link ArmoredOutputStream}.
     *
     * @param armor armored output stream
     * @param messageId message id
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-6.2">
     *     RFC 4880 - OpenPGP Message Format §6.2. Forming ASCII Armor</a>
     */
    public static void addMessageIdHeader(@Nonnull ArmoredOutputStream armor,
                                          @Nonnull String messageId) {
        if (!PATTERN_MESSAGE_ID.matcher(messageId).matches()) {
            throw new IllegalArgumentException("MessageIDs MUST consist of 32 printable characters.");
        }
        armor.addHeader(HEADER_MESSAGEID, messageId);
    }

    /**
     * Extract all ASCII armor header values of type comment from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of comment headers
     */
    @Nonnull
    public static List<String> getCommentHeaderValues(@Nonnull ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_COMMENT);
    }

    /**
     * Extract all ASCII armor header values of type message id from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of message-id headers
     */
    @Nonnull
    public static List<String> getMessageIdHeaderValues(@Nonnull ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_MESSAGEID);
    }

    /**
     * Return all ASCII armor header values of type hash-algorithm from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of hash headers
     */
    @Nonnull
    public static List<String> getHashHeaderValues(@Nonnull ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_HASH);
    }

    /**
     * Return a list of {@link HashAlgorithm} enums extracted from the hash header entries of the given
     * {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of hash algorithms from the ASCII header
     */
    @Nonnull
    public static List<HashAlgorithm> getHashAlgorithms(@Nonnull ArmoredInputStream armor) {
        List<String> algorithmNames = getHashHeaderValues(armor);
        List<HashAlgorithm> algorithms = new ArrayList<>();
        for (String name : algorithmNames) {
            HashAlgorithm algorithm = HashAlgorithm.fromName(name);
            if (algorithm != null) {
                algorithms.add(algorithm);
            }
        }
        return algorithms;
    }

    /**
     * Return all ASCII armor header values of type version from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of version headers
     */
    @Nonnull
    public static List<String> getVersionHeaderValues(@Nonnull ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_VERSION);
    }

    /**
     * Return all ASCII armor header values of type charset from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @return list of charset headers
     */
    @Nonnull
    public static List<String> getCharsetHeaderValues(@Nonnull ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_CHARSET);
    }

    /**
     * Return all ASCII armor header values of the given headerKey from the given {@link ArmoredInputStream}.
     *
     * @param armor armored input stream
     * @param headerKey ASCII armor header key
     * @return list of values for the header key
     */
    @Nonnull
    public static List<String> getArmorHeaderValues(@Nonnull ArmoredInputStream armor,
                                                    @Nonnull String headerKey) {
        String[] header = armor.getArmorHeaders();
        String key = headerKey + ": ";
        List<String> values = new ArrayList<>();
        for (String line : header) {
            if (line.startsWith(key)) {
                values.add(line.substring(key.length()));
            }
        }
        return values;
    }

    /**
     * Hacky workaround for #96.
     * For {@link PGPPublicKeyRingCollection#PGPPublicKeyRingCollection(InputStream, KeyFingerPrintCalculator)}
     * or {@link PGPSecretKeyRingCollection#PGPSecretKeyRingCollection(InputStream, KeyFingerPrintCalculator)}
     * to read all PGPKeyRings properly, we apparently have to make sure that the {@link InputStream} that is given
     * as constructor argument is a PGPUtil.BufferedInputStreamExt.
     * Since {@link PGPUtil#getDecoderStream(InputStream)} will return an {@link org.bouncycastle.bcpg.ArmoredInputStream}
     * if the underlying input stream contains armored data, we first dearmor the data ourselves to make sure that the
     * end-result is a PGPUtil.BufferedInputStreamExt.
     *
     * @param inputStream input stream
     * @return BufferedInputStreamExt
     *
     * @throws IOException in case of an IO error
     */
    @Nonnull
    public static InputStream getDecoderStream(@Nonnull InputStream inputStream)
            throws IOException {
        OpenPgpInputStream openPgpIn = new OpenPgpInputStream(inputStream);
        if (openPgpIn.isAsciiArmored()) {
            ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(openPgpIn);
            return PGPUtil.getDecoderStream(armorIn);
        }

        return openPgpIn;
    }
}
