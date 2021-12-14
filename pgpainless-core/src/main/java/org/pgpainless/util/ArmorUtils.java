// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.key.OpenPgpFingerprint;

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

    public static String toAsciiArmoredString(PGPSecretKeyRing secretKeys) throws IOException {
        MultiMap<String, String> header = keyToHeader(secretKeys);
        return toAsciiArmoredString(secretKeys.getEncoded(), header);
    }

    public static String toAsciiArmoredString(PGPPublicKeyRing publicKeys) throws IOException {
        MultiMap<String, String> header = keyToHeader(publicKeys);
        return toAsciiArmoredString(publicKeys.getEncoded(), header);
    }

    public static String toAsciiArmoredString(PGPSecretKeyRingCollection secretKeyRings) throws IOException {
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

    public static ArmoredOutputStream toAsciiArmoredStream(PGPKeyRing keyRing, OutputStream outputStream) {
        MultiMap<String, String> header = keyToHeader(keyRing);
        return toAsciiArmoredStream(outputStream, header);
    }

    public static ArmoredOutputStream toAsciiArmoredStream(OutputStream outputStream, MultiMap<String, String> header) {
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

    public static String toAsciiArmoredString(PGPPublicKeyRingCollection publicKeyRings) throws IOException {
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

    private static MultiMap<String, String> keyToHeader(PGPKeyRing keyRing) {
        MultiMap<String, String> header = new MultiMap<>();
        OpenPgpFingerprint fingerprint = OpenPgpFingerprint.of(keyRing);
        Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();

        header.put(HEADER_COMMENT, fingerprint.prettyPrint());
        if (userIds.hasNext()) {
            header.put(HEADER_COMMENT, userIds.next());
        }
        return header;
    }

    public static String toAsciiArmoredString(byte[] bytes) throws IOException {
        return toAsciiArmoredString(bytes, null);
    }

    public static String toAsciiArmoredString(byte[] bytes, MultiMap<String, String> additionalHeaderValues) throws IOException {
        return toAsciiArmoredString(new ByteArrayInputStream(bytes), additionalHeaderValues);
    }

    public static String toAsciiArmoredString(InputStream inputStream) throws IOException {
        return toAsciiArmoredString(inputStream, null);
    }

    public static void addHashAlgorithmHeader(ArmoredOutputStream armor, HashAlgorithm hashAlgorithm) {
        armor.addHeader(HEADER_HASH, hashAlgorithm.getAlgorithmName());
    }

    public static void addCommentHeader(ArmoredOutputStream armor, String comment) {
        armor.addHeader(HEADER_COMMENT, comment);
    }

    public static void addMessageIdHeader(ArmoredOutputStream armor, String messageId) {
        if (messageId == null) {
            throw new NullPointerException("MessageID cannot be null.");
        }
        if (!PATTERN_MESSAGE_ID.matcher(messageId).matches()) {
            throw new IllegalArgumentException("MessageIDs MUST consist of 32 printable characters.");
        }
        armor.addHeader(HEADER_MESSAGEID, messageId);
    }

    public static String toAsciiArmoredString(InputStream inputStream, MultiMap<String, String> additionalHeaderValues) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = toAsciiArmoredStream(out, additionalHeaderValues);
        Streams.pipeAll(inputStream, armor);
        armor.close();

        return out.toString();
    }

    public static ArmoredOutputStream createArmoredOutputStreamFor(PGPKeyRing keyRing, OutputStream outputStream) {
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(outputStream);
        MultiMap<String, String> headerMap = keyToHeader(keyRing);
        for (String header : headerMap.keySet()) {
            for (String value : headerMap.get(header)) {
                armor.addHeader(header, value);
            }
        }

        return armor;
    }

    public static List<String> getCommentHeaderValues(ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_COMMENT);
    }

    public static List<String> getMessageIdHeaderValues(ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_MESSAGEID);
    }

    public static List<String> getHashHeaderValues(ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_HASH);
    }

    public static List<HashAlgorithm> getHashAlgorithms(ArmoredInputStream armor) {
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

    public static List<String> getVersionHeaderValues(ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_VERSION);
    }

    public static List<String> getCharsetHeaderValues(ArmoredInputStream armor) {
        return getArmorHeaderValues(armor, HEADER_CHARSET);
    }

    public static List<String> getArmorHeaderValues(ArmoredInputStream armor, String headerKey) {
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
     * if the underlying input stream contains armored data, we have to nest two method calls to make sure that the
     * end-result is a PGPUtil.BufferedInputStreamExt.
     *
     * This is a hacky solution.
     *
     * @param inputStream input stream
     * @return BufferedInputStreamExt
     */
    public static InputStream getDecoderStream(InputStream inputStream) throws IOException {
        BufferedInputStream buf = new BufferedInputStream(inputStream, 512);
        InputStream decoderStream = PGPUtilWrapper.getDecoderStream(buf);
        // Data is not armored -> return
        if (decoderStream instanceof BufferedInputStream) {
            return decoderStream;
        }
        // Wrap armored input stream with fix for #159
        decoderStream = CRCingArmoredInputStreamWrapper.possiblyWrap(decoderStream);

        decoderStream = PGPUtil.getDecoderStream(decoderStream);
        return decoderStream;
    }
}
