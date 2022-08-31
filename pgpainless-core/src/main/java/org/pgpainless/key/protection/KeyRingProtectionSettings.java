// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import javax.annotation.Nonnull;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

/**
 * Secret key protection settings for iterated and salted S2K.
 */
public class KeyRingProtectionSettings {

    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final int s2kCount;

    /**
     * Create a {@link KeyRingProtectionSettings} object using the given encryption algorithm, SHA1 and
     * 65536 iterations.
     *
     * @param encryptionAlgorithm encryption algorithm
     */
    public KeyRingProtectionSettings(@Nonnull SymmetricKeyAlgorithm encryptionAlgorithm) {
        this(encryptionAlgorithm, HashAlgorithm.SHA1, 0x60); // Same s2kCount (encoded) as used in BC.
    }

    /**
     * Constructor for custom salted and iterated S2K protection settings.
     * The salt gets randomly chosen by the library each time.
     *
     * Note, that the s2kCount is the already encoded single-octet number.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-3.7.1.3">Encoding Formula</a>
     *
     * @param encryptionAlgorithm encryption algorithm
     * @param hashAlgorithm hash algorithm
     * @param s2kCount encoded s2k iteration count
     */
    public KeyRingProtectionSettings(@Nonnull SymmetricKeyAlgorithm encryptionAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, int s2kCount) {
        this.encryptionAlgorithm = validateEncryptionAlgorithm(encryptionAlgorithm);
        this.hashAlgorithm = hashAlgorithm;
        if (s2kCount < 1) {
            throw new IllegalArgumentException("s2kCount cannot be less than 1.");
        }
        this.s2kCount = s2kCount;
    }

    private static SymmetricKeyAlgorithm validateEncryptionAlgorithm(SymmetricKeyAlgorithm encryptionAlgorithm) {
        switch (encryptionAlgorithm) {
            case NULL:
                throw new IllegalArgumentException("Unencrypted is not allowed here!");
            default:
                return encryptionAlgorithm;
        }
    }

    /**
     * Secure default settings using {@link SymmetricKeyAlgorithm#AES_256}, {@link HashAlgorithm#SHA256}
     * and an iteration count of 65536.
     *
     * @return secure protection settings
     */
    public static KeyRingProtectionSettings secureDefaultSettings() {
        return new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA256, 0x60);
    }

    /**
     * Return the encryption algorithm.
     *
     * @return encryption algorithm
     */
    public @Nonnull SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    /**
     * Return the hash algorithm.
     *
     * @return hash algorithm
     */
    public @Nonnull HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Return the (encoded!) s2k iteration count.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-3.7.1.3">Encoding Formula</a>
     *
     * @return encoded s2k count
     */
    public int getS2kCount() {
        return s2kCount;
    }
}
