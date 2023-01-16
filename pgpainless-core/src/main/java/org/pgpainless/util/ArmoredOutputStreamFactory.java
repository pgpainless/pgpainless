// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.pgpainless.encryption_signing.ProducerOptions;

/**
 * Factory to create configured {@link ArmoredOutputStream ArmoredOutputStreams}.
 * The configuration entails setting custom version and comment headers.
 */
public final class ArmoredOutputStreamFactory {

    /**
     * Name of the program.
     */
    public static final String PGPAINLESS = "PGPainless";
    private static String version = PGPAINLESS;
    private static String[] comment = new String[0];

    private ArmoredOutputStreamFactory() {

    }

    /**
     * Wrap an {@link OutputStream} inside a preconfigured {@link ArmoredOutputStream}.
     *
     * @param outputStream inner stream
     * @return armored output stream
     */
    public static ArmoredOutputStream get(OutputStream outputStream) {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream);
        armoredOutputStream.clearHeaders();
        if (version != null && !version.isEmpty()) {
            armoredOutputStream.setHeader(ArmorUtils.HEADER_VERSION, version);
        }

        for (String comment : comment) {
            ArmorUtils.addCommentHeader(armoredOutputStream, comment);
        }
        return armoredOutputStream;
    }

    /**
     * Return an instance of the {@link ArmoredOutputStream} which might have pre-populated armor headers.
     *
     * @param outputStream output stream
     * @param options options
     * @return armored output stream
     */
    public static ArmoredOutputStream get(OutputStream outputStream, ProducerOptions options) {
        if (options.isHideArmorHeaders()) {
            ArmoredOutputStream armorOut = new ArmoredOutputStream(outputStream);
            armorOut.clearHeaders();
            return armorOut;
        } else {
            return get(outputStream);
        }
    }

    /**
     * Overwrite the version header of ASCII armors with a custom value.
     * Newlines in the version info string result in multiple version header entries.
     * If this is set to <pre>null</pre>, then the version header is omitted altogether.
     *
     * @param versionString version string
     */
    public static void setVersionInfo(String versionString) {
        if (versionString == null) {
            version = null;
            return;
        }
        String trimmed = versionString.trim();
        if (trimmed.isEmpty()) {
            version = null;
        } else {
            version = trimmed;
        }
    }

    /**
     * Reset the version header to its default value of {@link #PGPAINLESS}.
     */
    public static void resetVersionInfo() {
        version = PGPAINLESS;
    }

    /**
     * Set a comment header value in the ASCII armor header.
     * If the comment contains newlines, it will be split into multiple header entries.
     *
     * @see org.pgpainless.encryption_signing.ProducerOptions#setComment(String)  for how to set comments for
     * individual messages.
     *
     * @param commentString comment
     */
    public static void setComment(String commentString) {
        if (commentString == null) {
            throw new IllegalArgumentException("Comment cannot be null.");
        }
        String trimmed = commentString.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Comment cannot be empty.");
        }

        String[] lines = commentString.split("\n");
        comment = lines;
    }

    /**
     * Reset to the default of no comment headers.
     */
    public static void resetComment() {
        comment = new String[0];
    }
}
