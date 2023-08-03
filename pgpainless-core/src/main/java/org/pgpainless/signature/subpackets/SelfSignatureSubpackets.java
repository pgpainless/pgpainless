// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.pgpainless.algorithm.AEADAlgorithmCombination;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public interface SelfSignatureSubpackets extends BaseSignatureSubpackets {

    interface Callback extends SignatureSubpacketCallback<SelfSignatureSubpackets> {

    }

    SelfSignatureSubpackets setKeyFlags(KeyFlag... keyFlags);

    default SelfSignatureSubpackets setKeyFlags(List<KeyFlag> keyFlags) {
        KeyFlag[] flags = keyFlags.toArray(new KeyFlag[0]);
        return setKeyFlags(flags);
    }

    SelfSignatureSubpackets setKeyFlags(boolean isCritical, KeyFlag... keyFlags);

    SelfSignatureSubpackets setKeyFlags(@Nullable KeyFlags keyFlags);

    SelfSignatureSubpackets setPrimaryUserId();

    SelfSignatureSubpackets setPrimaryUserId(boolean isCritical);

    SelfSignatureSubpackets setPrimaryUserId(@Nullable PrimaryUserID primaryUserId);

    SelfSignatureSubpackets setKeyExpirationTime(@Nonnull PGPPublicKey key, @Nonnull Date keyExpirationTime);

    SelfSignatureSubpackets setKeyExpirationTime(@Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime);

    SelfSignatureSubpackets setKeyExpirationTime(boolean isCritical, @Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime);

    SelfSignatureSubpackets setKeyExpirationTime(boolean isCritical, long secondsFromCreationToExpiration);

    SelfSignatureSubpackets setKeyExpirationTime(@Nullable KeyExpirationTime keyExpirationTime);

    SelfSignatureSubpackets setPreferredAEADCiphersuites(AEADAlgorithmCombination... algorithms);

    SelfSignatureSubpackets setPreferredAEADCiphersuites(Set<AEADAlgorithmCombination> algorithms);

    SelfSignatureSubpackets setPreferredAEADCiphersuites(boolean isCritical, Set<AEADAlgorithmCombination> algorithms);

    SelfSignatureSubpackets setPreferredAEADCiphersuites(@Nullable PreferredAEADCiphersuites algorithms);

    SelfSignatureSubpackets setPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms);

    SelfSignatureSubpackets setPreferredCompressionAlgorithms(Set<CompressionAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredCompressionAlgorithms(boolean isCritical, Set<CompressionAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredCompressionAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SelfSignatureSubpackets setPreferredHashAlgorithms(HashAlgorithm... algorithms);

    SelfSignatureSubpackets setPreferredHashAlgorithms(Set<HashAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredHashAlgorithms(boolean isCritical, Set<HashAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredHashAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SelfSignatureSubpackets setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm... algorithms);

    SelfSignatureSubpackets setPreferredSymmetricKeyAlgorithms(Set<SymmetricKeyAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredSymmetricKeyAlgorithms(boolean isCritical, Set<SymmetricKeyAlgorithm> algorithms);

    SelfSignatureSubpackets setPreferredSymmetricKeyAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SelfSignatureSubpackets addRevocationKey(@Nonnull PGPPublicKey revocationKey);

    SelfSignatureSubpackets addRevocationKey(boolean isCritical, @Nonnull PGPPublicKey revocationKey);

    SelfSignatureSubpackets addRevocationKey(boolean isCritical, boolean isSensitive, @Nonnull PGPPublicKey revocationKey);

    SelfSignatureSubpackets addRevocationKey(@Nonnull RevocationKey revocationKey);

    SelfSignatureSubpackets clearRevocationKeys();

    SelfSignatureSubpackets setFeatures(Feature... features);

    SelfSignatureSubpackets setFeatures(boolean isCritical, Feature... features);

    SelfSignatureSubpackets setFeatures(@Nullable Features features);
}
