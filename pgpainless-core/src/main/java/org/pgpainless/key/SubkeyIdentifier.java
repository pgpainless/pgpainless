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
package org.pgpainless.key;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;

/**
 * Tuple class used to identify a subkey by fingerprints of the primary key of the subkeys key ring,
 * as well as the subkeys fingerprint.
 */
public class SubkeyIdentifier {

    private final OpenPgpV4Fingerprint primaryKeyFingerprint;
    private final OpenPgpV4Fingerprint subkeyFingerprint;

    /**
     * Create a {@link SubkeyIdentifier} from a {@link PGPKeyRing} and the subkeys key id.
     * {@link #getPrimaryKeyFingerprint()} will return the {@link OpenPgpV4Fingerprint} of the keyrings primary key,
     * while {@link #getSubkeyFingerprint()} will return the subkeys fingerprint.
     *
     * @param keyRing keyring the subkey belongs to
     * @param keyId keyid of the subkey
     */
    public SubkeyIdentifier(@Nonnull PGPKeyRing keyRing, long keyId) {
        this(new OpenPgpV4Fingerprint(keyRing.getPublicKey()), new OpenPgpV4Fingerprint(keyRing.getPublicKey(keyId)));
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
     * Return the {@link OpenPgpV4Fingerprint} of the identified subkey.
     *
     * @return subkey fingerprint
     */
    public @Nonnull OpenPgpV4Fingerprint getSubkeyFingerprint() {
        return subkeyFingerprint;
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
