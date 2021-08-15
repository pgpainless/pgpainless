/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util;

import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;

/**
 * Factory to create configured {@link ArmoredOutputStream ArmoredOutputStreams}.
 * The configuration entails setting custom version and comment headers.
 */
public final class ArmoredOutputStreamFactory {

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
        armoredOutputStream.setHeader(ArmorUtils.HEADER_VERSION, version);
        for (String comment : comment) {
            ArmorUtils.addCommentHeader(armoredOutputStream, comment);
        }
        return armoredOutputStream;
    }

    /**
     * Overwrite the version header of ASCII armors with a custom value.
     * Newlines in the version info string result in multiple version header entries.
     *
     * @param versionString version string
     */
    public static void setVersionInfo(String versionString) {
        if (versionString == null || versionString.trim().isEmpty()) {
            throw new IllegalArgumentException("Version Info MUST NOT be null NOR empty.");
        }
        version = versionString;
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
