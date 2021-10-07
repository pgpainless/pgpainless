// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.util.NoSuchElementException;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Tuple class used to identify a subkey by fingerprints of the primary key of the subkeys key ring,
 * as well as the subkeys fingerprint.
 */
public class SubkeyIdentifier {

    private final OpenPgpV4Fingerprint primaryKeyFingerprint;
    private final OpenPgpV4Fingerprint subkeyFingerprint;

    /**
     * Create a {@link SubkeyIdentifier} from a {@link PGPKeyRing}.
     * The identifier will point to the primary key of the provided ring.
     *
     * @param keyRing key ring
     */
    public SubkeyIdentifier(PGPKeyRing keyRing) {
        this(keyRing, keyRing.getPublicKey().getKeyID());
    }

    /**
     * Create a {@link SubkeyIdentifier} from a {@link PGPKeyRing} and the subkeys key id.
     * {@link #getPrimaryKeyFingerprint()} will return the {@link OpenPgpV4Fingerprint} of the keyrings primary key,
     * while {@link #getSubkeyFingerprint()} will return the subkeys fingerprint.
     *
     * @param keyRing keyring the subkey belongs to
     * @param keyId keyid of the subkey
     */
    public SubkeyIdentifier(@Nonnull PGPKeyRing keyRing, long keyId) {
        PGPPublicKey subkey = keyRing.getPublicKey(keyId);
        if (subkey == null) {
            throw new NoSuchElementException("Key ring does not contain subkey with id " + Long.toHexString(keyId));
        }
        this.primaryKeyFingerprint = new OpenPgpV4Fingerprint(keyRing);
        this.subkeyFingerprint = new OpenPgpV4Fingerprint(subkey);
    }

    public SubkeyIdentifier(@Nonnull PGPKeyRing keyRing, @Nonnull OpenPgpV4Fingerprint subkeyFingerprint) {
        this(new OpenPgpV4Fingerprint(keyRing), subkeyFingerprint);
    }

    /**
     * Create a {@link SubkeyIdentifier} that identifies the primary key with the given fingerprint.
     * This means, both {@link #getPrimaryKeyFingerprint()} and {@link #getSubkeyFingerprint()} return the same.
     *
     * @param primaryKeyFingerprint fingerprint of the identified key
     */
    public SubkeyIdentifier(@Nonnull OpenPgpV4Fingerprint primaryKeyFingerprint) {
        this(primaryKeyFingerprint, primaryKeyFingerprint);
    }

    /**
     * Create a {@link SubkeyIdentifier} which points to the subkey with the given subkeyFingerprint,
     * which has a primary key with the given primaryKeyFingerprint.
     *
     * @param primaryKeyFingerprint fingerprint of the primary key
     * @param subkeyFingerprint fingerprint of the subkey
     */
    public SubkeyIdentifier(@Nonnull OpenPgpV4Fingerprint primaryKeyFingerprint, @Nonnull OpenPgpV4Fingerprint subkeyFingerprint) {
        this.primaryKeyFingerprint = primaryKeyFingerprint;
        this.subkeyFingerprint = subkeyFingerprint;
    }

    public @Nonnull OpenPgpV4Fingerprint getFingerprint() {
        return getSubkeyFingerprint();
    }

    public long getKeyId() {
        return getSubkeyId();
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of the primary key of the identified key.
     * This might be the same as {@link #getSubkeyFingerprint()} if the identified subkey is the primary key.
     *
     * @return primary key fingerprint
     */
    public @Nonnull OpenPgpV4Fingerprint getPrimaryKeyFingerprint() {
        return primaryKeyFingerprint;
    }

    /**
     * Return the key id of the primary key of the identified key.
     * This might be the same as {@link #getSubkeyId()} if the identified subkey is the primary key.
     *
     * @return primary key id
     */
    public long getPrimaryKeyId() {
        return getPrimaryKeyFingerprint().getKeyId();
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of the identified subkey.
     *
     * @return subkey fingerprint
     */
    public @Nonnull OpenPgpV4Fingerprint getSubkeyFingerprint() {
        return subkeyFingerprint;
    }

    /**
     * Return the key id of the identified subkey.
     *
     * @return subkey id
     */
    public long getSubkeyId() {
        return getSubkeyFingerprint().getKeyId();
    }

    @Override
    public int hashCode() {
        return primaryKeyFingerprint.hashCode() * 31 + subkeyFingerprint.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SubkeyIdentifier)) {
            return false;
        }
        SubkeyIdentifier other = (SubkeyIdentifier) obj;
        return getPrimaryKeyFingerprint().equals(other.getPrimaryKeyFingerprint())
                && getSubkeyFingerprint().equals(other.getSubkeyFingerprint());
    }

    @Override
    public String toString() {
        return getSubkeyFingerprint() + " " + getPrimaryKeyFingerprint();
    }
}
