// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

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
 * This class represents a hex encoded, upper case OpenPGP v5 or v6 fingerprint.
 * Since both fingerprints use the same format, this class is used when parsing the fingerprint without knowing the
 * key version.
 */
public class _64DigitFingerprint extends OpenPgpFingerprint {

    /**
     * Create an {@link _64DigitFingerprint}.
     *
     * @param fingerprint uppercase hexadecimal fingerprint of length 64
     */
    protected _64DigitFingerprint(@Nonnull String fingerprint) {
        super(fingerprint);
    }

    protected _64DigitFingerprint(@Nonnull byte[] bytes) {
        super(Hex.encode(bytes));
    }

    protected _64DigitFingerprint(@Nonnull PGPPublicKey key) {
        super(key);
    }

    protected _64DigitFingerprint(@Nonnull PGPSecretKey key) {
        this(key.getPublicKey());
    }

    protected _64DigitFingerprint(@Nonnull PGPPublicKeyRing ring) {
        super(ring);
    }

    protected _64DigitFingerprint(@Nonnull PGPSecretKeyRing ring) {
        super(ring);
    }

    protected _64DigitFingerprint(@Nonnull PGPKeyRing ring) {
        super(ring);
    }

    @Override
    public int getVersion() {
        return -1; // might be v5 or v6
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
