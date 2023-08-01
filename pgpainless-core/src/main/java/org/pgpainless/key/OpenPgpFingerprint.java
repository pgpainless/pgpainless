// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.nio.charset.Charset;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;

/**
 * Abstract super class of different version OpenPGP fingerprints.
 *
 */
public abstract class OpenPgpFingerprint implements CharSequence, Comparable<OpenPgpFingerprint> {
    @SuppressWarnings("CharsetObjectCanBeUsed")
    protected static final Charset utf8 = Charset.forName("UTF-8");
    protected final String fingerprint;

    /**
     * Return the fingerprint of the given key.
     * This method automatically matches key versions to fingerprint implementations.
     *
     * @param key key
     * @return fingerprint
     */
    public static OpenPgpFingerprint of(PGPSecretKey key) {
        return of(key.getPublicKey());
    }

    /**
     * Return the fingerprint of the given key.
     * This method automatically matches key versions to fingerprint implementations.
     *
     * @param key key
     * @return fingerprint
     */
    public static OpenPgpFingerprint of(PGPPublicKey key) {
        if (key.getVersion() == 4) {
            return new OpenPgpV4Fingerprint(key);
        }
        if (key.getVersion() == 5) {
            return new OpenPgpV5Fingerprint(key);
        }
        if (key.getVersion() == 6) {
            return new OpenPgpV6Fingerprint(key);
        }
        throw new IllegalArgumentException("OpenPGP keys of version " + key.getVersion() + " are not supported.");
    }

    /**
     * Return the fingerprint of the primary key of the given key ring.
     * This method automatically matches key versions to fingerprint implementations.
     *
     * @param ring key ring
     * @return fingerprint
     */
    public static OpenPgpFingerprint of(PGPKeyRing ring) {
        return of(ring.getPublicKey());
    }

    /**
     * Try to parse an {@link OpenPgpFingerprint} from the given fingerprint string.
     * If the trimmed fingerprint without whitespace is 64 characters long, it is either a v5 or v6 fingerprint.
     * In this case, we return a {@link _64DigitFingerprint}. Since this is ambiguous, it is generally recommended
     * to know the version of the key beforehand.
     *
     * @param fingerprint fingerprint
     * @return parsed fingerprint
     * @deprecated Use the constructor methods of the versioned fingerprint subclasses instead.
     */
    @Deprecated
    public static OpenPgpFingerprint parse(String fingerprint) {
        String fp = fingerprint.replace(" ", "").trim().toUpperCase();
        if (fp.matches("^[0-9A-F]{40}$")) {
            return new OpenPgpV4Fingerprint(fp);
        }
        if (fp.matches("^[0-9A-F]{64}$")) {
            // Might be v5 or v6 :/
            return new _64DigitFingerprint(fp);
        }
        throw new IllegalArgumentException("Fingerprint does not appear to match any known fingerprint patterns.");
    }

    /**
     * Parse a binary OpenPGP fingerprint into an {@link OpenPgpFingerprint} object.
     *
     * @param binaryFingerprint binary representation of the fingerprint
     * @return parsed fingerprint
     * @deprecated use the parse() methods of the versioned fingerprint subclasses instead.
     */
    @Deprecated
    public static OpenPgpFingerprint parseFromBinary(byte[] binaryFingerprint) {
        String hex = Hex.toHexString(binaryFingerprint).toUpperCase();
        return parse(hex);
    }

    public OpenPgpFingerprint(String fingerprint) {
        String fp = fingerprint.replace(" ", "").trim().toUpperCase();
        if (!isValid(fp)) {
            throw new IllegalArgumentException(
                    String.format("Fingerprint '%s' does not appear to be a valid OpenPGP V%d fingerprint.", fingerprint, getVersion())
            );
        }
        this.fingerprint = fp;
    }

    public OpenPgpFingerprint(@Nonnull byte[] bytes) {
        this(new String(bytes, utf8));
    }

    public OpenPgpFingerprint(PGPPublicKey key) {
        this(Hex.encode(key.getFingerprint()));
        if (key.getVersion() != getVersion()) {
            throw new IllegalArgumentException(String.format("Key is not a v%d OpenPgp key.", getVersion()));
        }
    }

    public OpenPgpFingerprint(@Nonnull PGPPublicKeyRing ring) {
        this(ring.getPublicKey());
    }

    public OpenPgpFingerprint(@Nonnull PGPSecretKeyRing ring) {
        this(ring.getPublicKey());
    }

    public OpenPgpFingerprint(@Nonnull PGPKeyRing ring) {
        this(ring.getPublicKey());
    }

    /**
     * Return the version of the fingerprint.
     *
     * @return version
     */
    public abstract int getVersion();

    /**
     * Check, whether the fingerprint consists of 40 valid hexadecimal characters.
     * @param fp fingerprint to check.
     * @return true if fingerprint is valid.
     */
    protected abstract boolean isValid(@Nonnull String fp);

    /**
     * Return the key id of the OpenPGP public key this {@link OpenPgpFingerprint} belongs to.
     * This method can be implemented for V4 and V5 fingerprints.
     * V3 key-IDs cannot be derived from the fingerprint, but we don't care, since V3 is deprecated.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4880#section-12.2">
     *     RFC-4880 §12.2: Key IDs and Fingerprints</a>
     * @return key id
     */
    public abstract long getKeyId();

    @Override
    public int length() {
        return fingerprint.length();
    }

    @Override
    public char charAt(int i) {
        return fingerprint.charAt(i);
    }

    @Override
    public CharSequence subSequence(int i, int i1) {
        return fingerprint.subSequence(i, i1);
    }

    @Override
    @Nonnull
    public String toString() {
        return fingerprint;
    }

    /**
     * Return a pretty printed representation of the fingerprint.
     *
     * @return pretty printed fingerprint
     */
    public abstract String prettyPrint();
}
