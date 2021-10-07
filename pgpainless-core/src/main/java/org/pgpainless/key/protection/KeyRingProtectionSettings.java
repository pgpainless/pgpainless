// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import javax.annotation.Nonnull;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class KeyRingProtectionSettings {

    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final int s2kCount;

    public KeyRingProtectionSettings(@Nonnull SymmetricKeyAlgorithm encryptionAlgorithm) {
        this(encryptionAlgorithm, HashAlgorithm.SHA1, 0x60); // Same s2kCount as used in BC.
    }

    public KeyRingProtectionSettings(@Nonnull SymmetricKeyAlgorithm encryptionAlgorithm, @Nonnull HashAlgorithm hashAlgorithm, int s2kCount) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        if (s2kCount < 1) {
            throw new IllegalArgumentException("s2kCount cannot be less than 1.");
        }
        this.s2kCount = s2kCount;
    }

    public static KeyRingProtectionSettings secureDefaultSettings() {
        return new KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256);
    }

    public @Nonnull SymmetricKeyAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public @Nonnull HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public int getS2kCount() {
        return s2kCount;
    }
}
