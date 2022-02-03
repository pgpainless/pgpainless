// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.encoders.Base64;
import org.pgpainless.key.OpenPgpFingerprint;
import pgp.certificate_store.Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CertificateFactory {

    public static Certificate certificateFromPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        return new Certificate() {
            @Override
            public String getFingerprint() {
                return OpenPgpFingerprint.of(publicKeyRing).toString().toLowerCase();
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return new ByteArrayInputStream(publicKeyRing.getEncoded());
            }

            @Override
            public String getTag() throws IOException {
                MessageDigest digest;
                try {
                    digest = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    throw new AssertionError("No MessageDigest for SHA-256 instantiated, although BC is on the classpath: " + e.getMessage());
                }
                digest.update(publicKeyRing.getEncoded());
                return Base64.toBase64String(digest.digest());
            }
        };
    }
}
