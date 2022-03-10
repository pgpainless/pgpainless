// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

import javax.annotation.Nonnull;
import java.nio.Buffer;
import java.nio.ByteBuffer;

/**
 * This class represents a hex encoded, upper case OpenPGP v5 fingerprint.
 */
public class OpenPgpV5Fingerprint extends OpenPgpFingerprint {

    /**
     * Create an {@link OpenPgpV5Fingerprint}.
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 64
     */
    public OpenPgpV5Fingerprint(@Nonnull String fingerprint) {
        super(fingerprint);
    }

    public OpenPgpV5Fingerprint(@Nonnull byte[] bytes) {
        super(Hex.encode(bytes));
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPPublicKey key) {
        super(key);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPSecretKey key) {
        this(key.getPublicKey());
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPPublicKeyRing ring) {
        super(ring);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPSecretKeyRing ring) {
        super(ring);
    }

    public OpenPgpV5Fingerprint(@Nonnull PGPKeyRing ring) {
        super(ring);
    }

    @Override
    public int getVersion() {
        return 5;
    }

    @Override
    protected boolean isValid(@Nonnull String fp) {
        return fp.matches("^[0-9A-F]{64}$");
    }

    @Override
    public long getKeyId() {
        byte[] bytes = Hex.decode(toString().getBytes(utf8));
        ByteBuffer buf = ByteBuffer.wrap(bytes);

        // The key id is the left-most 8 bytes (conveniently a long).
        // We have to cast here in order to be compatible with java 8
        // https://github.com/eclipse/jetty.project/issues/3244
        ((Buffer) buf).position(0);

        return buf.getLong();
    }

    @Override
    public String prettyPrint() {
        String fp = toString();
        StringBuilder pretty = new StringBuilder();

        for (int i = 0; i < 4; i++) {
            pretty.append(fp, i * 8, (i + 1) * 8).append(' ');
        }
        pretty.append(' ');
        for (int i = 4; i < 7; i++) {
            pretty.append(fp, i * 8, (i + 1) * 8).append(' ');
        }
        pretty.append(fp, 56, 64);
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

    @Override
    public int compareTo(OpenPgpFingerprint openPgpFingerprint) {
        return toString().compareTo(openPgpFingerprint.toString());
    }
}
