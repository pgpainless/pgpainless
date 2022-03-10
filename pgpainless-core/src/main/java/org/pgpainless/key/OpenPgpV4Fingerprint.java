// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class represents a hex encoded, uppercase OpenPGP v4 fingerprint.
 */
public class OpenPgpV4Fingerprint extends OpenPgpFingerprint {

    public static final String SCHEME = "openpgp4fpr";

    /**
     * Create an {@link OpenPgpV4Fingerprint}.
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 40
     */
    public OpenPgpV4Fingerprint(@Nonnull String fingerprint) {
        super(fingerprint);
    }

    public OpenPgpV4Fingerprint(@Nonnull byte[] bytes) {
        super(Hex.encode(bytes));
    }

    public OpenPgpV4Fingerprint(@Nonnull PGPPublicKey key) {
        super(key);
    }

    public OpenPgpV4Fingerprint(@Nonnull PGPSecretKey key) {
        this(key.getPublicKey());
    }

    public OpenPgpV4Fingerprint(@Nonnull PGPPublicKeyRing ring) {
        super(ring);
    }

    public OpenPgpV4Fingerprint(@Nonnull PGPSecretKeyRing ring) {
        super(ring);
    }

    public OpenPgpV4Fingerprint(@Nonnull PGPKeyRing ring) {
        super(ring);
    }

    @Override
    public int getVersion() {
        return 4;
    }

    @Override
    protected boolean isValid(@Nonnull String fp) {
        return fp.matches("^[0-9A-F]{40}$");
    }

    @Override
    public long getKeyId() {
        byte[] bytes = Hex.decode(toString().getBytes(utf8));
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        // The key id is the right-most 8 bytes (conveniently a long)
        // We have to cast here in order to be compatible with java 8
        // https://github.com/eclipse/jetty.project/issues/3244
        ((Buffer) buf).position(12); // 20 - 8 bytes = offset 12

        return buf.getLong();
    }

    @Override
    public String prettyPrint() {
        String fp = toString();
        StringBuilder pretty = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            pretty.append(fp, i * 4, (i + 1) * 4).append(' ');
        }
        pretty.append(' ');
        for (int i = 5; i < 9; i++) {
            pretty.append(fp, i * 4, (i + 1) * 4).append(' ');
        }
        pretty.append(fp, 36, 40);
        return pretty.toString();
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }

        if (!(other instanceof CharSequence)) {
            return false;
        }

        return this.toString().equals(other.toString());
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    /**
     * Return the fingerprint as an openpgp4fpr {@link URI}.
     * An example would be 'openpgp4fpr:7F9116FEA90A5983936C7CFAA027DB2F3E1E118A'.
     *
     * @return openpgp4fpr fingerprint uri
     * @see <a href="https://metacode.biz/openpgp/openpgp4fpr">openpgp4fpr URI scheme</a>
     */
    public URI toUri() {
        try {
            return new URI(OpenPgpV4Fingerprint.SCHEME, toString(), null);
        } catch (URISyntaxException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Convert an openpgp4fpr URI to an {@link OpenPgpV4Fingerprint}.
     *
     * @param uri {@link URI} with scheme 'openpgp4fpr'
     * @return fingerprint parsed from the uri
     * @see <a href="https://metacode.biz/openpgp/openpgp4fpr">openpgp4fpr URI scheme</a>
     */
    public static OpenPgpV4Fingerprint fromUri(URI uri) {
        if (!SCHEME.equals(uri.getScheme())) {
            throw new IllegalArgumentException("URI scheme MUST equal '" + SCHEME + "'");
        }
        return new OpenPgpV4Fingerprint(uri.getSchemeSpecificPart());
    }

    @Override
    public int compareTo(@Nonnull OpenPgpFingerprint openPgpFingerprint) {
        return toString().compareTo(openPgpFingerprint.toString());
    }
}
