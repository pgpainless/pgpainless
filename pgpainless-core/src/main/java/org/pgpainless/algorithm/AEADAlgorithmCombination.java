// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;

public final class AEADAlgorithmCombination {

    private final AEADAlgorithm aeadAlgorithm;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;

    /**
     * AES-128 + OCB is a MUST implement and is therefore implicitly supported.
     *
     * @see <a href="https://openpgp-wg.gitlab.io/rfc4880bis/#name-preferred-aead-ciphersuites">
     * Crypto-Refresh § 5.2.3.15. Preferred AEAD Ciphersuites</a>
     */
    public static AEADAlgorithmCombination AES_128_OCB = AEADAlgorithmCombination.from(
            SymmetricKeyAlgorithm.AES_128, AEADAlgorithm.OCB);

    private AEADAlgorithmCombination(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                    @Nonnull AEADAlgorithm aeadAlgorithm) {
        this.aeadAlgorithm = aeadAlgorithm;
        this.symmetricKeyAlgorithm = requireNotUnencrypted(symmetricKeyAlgorithm);
    }

    private static SymmetricKeyAlgorithm requireNotUnencrypted(SymmetricKeyAlgorithm algorithm) {
        if (algorithm == SymmetricKeyAlgorithm.NULL) {
            throw new IllegalArgumentException("Symmetric Key Algorithm MUST NOT be NULL (unencrypted).");
        }
        return algorithm;
    }

    @Nonnull
    public AEADAlgorithm getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    @Nonnull
    public SymmetricKeyAlgorithm getSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }

    public static AEADAlgorithmCombination from(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                                @Nonnull AEADAlgorithm aeadAlgorithm) {
        return new AEADAlgorithmCombination(symmetricKeyAlgorithm, aeadAlgorithm);
    }

    @Nullable
    public static AEADAlgorithmCombination from(PreferredAEADCiphersuites.Combination combination) {
        return fromIds(combination.getSymmetricAlgorithm(), combination.getAeadAlgorithm());
    }

    @Nonnull
    public static AEADAlgorithmCombination requireFrom(PreferredAEADCiphersuites.Combination combination) {
        return requireFromIds(combination.getSymmetricAlgorithm(), combination.getAeadAlgorithm());
    }

    @Nullable
    public static AEADAlgorithmCombination fromIds(int symmetricAlgorithmId, int aeadAlgorithmId) {
        SymmetricKeyAlgorithm symmetric = SymmetricKeyAlgorithm.fromId(symmetricAlgorithmId);
        AEADAlgorithm aead = AEADAlgorithm.fromId(aeadAlgorithmId);

        if (symmetric == null || aead == null) {
            return null;
        }

        return new AEADAlgorithmCombination(symmetric, aead);
    }

    @Nonnull
    public static AEADAlgorithmCombination requireFromIds(int symmetricAlgorithmId, int aeadAlgorithmId) {
        return from(SymmetricKeyAlgorithm.requireFromId(symmetricAlgorithmId), AEADAlgorithm.requireFromId(aeadAlgorithmId));
    }
}
