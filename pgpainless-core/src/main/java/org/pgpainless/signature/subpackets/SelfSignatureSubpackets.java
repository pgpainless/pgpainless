// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.subpackets;

import java.util.Date;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public interface SelfSignatureSubpackets extends BaseSignatureSubpackets {

    interface Callback {
        default void modifyHashedSubpackets(SelfSignatureSubpackets subpackets) {

        }

        default void modifyUnhashedSubpackets(SelfSignatureSubpackets subpackets) {

        }
    }

    SignatureSubpacketGeneratorWrapper setKeyFlags(KeyFlag... keyFlags);

    SignatureSubpacketGeneratorWrapper setKeyFlags(boolean isCritical, KeyFlag... keyFlags);

    SignatureSubpacketGeneratorWrapper setKeyFlags(@Nullable KeyFlags keyFlags);

    SignatureSubpacketGeneratorWrapper setPrimaryUserId();

    SignatureSubpacketGeneratorWrapper setPrimaryUserId(boolean isCritical);

    SignatureSubpacketGeneratorWrapper setPrimaryUserId(@Nullable PrimaryUserID primaryUserId);

    SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nonnull PGPPublicKey key, @Nonnull Date keyExpirationTime);

    SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime);

    SignatureSubpacketGeneratorWrapper setKeyExpirationTime(boolean isCritical, @Nonnull Date keyCreationTime, @Nonnull Date keyExpirationTime);

    SignatureSubpacketGeneratorWrapper setKeyExpirationTime(boolean isCritical, long secondsFromCreationToExpiration);

    SignatureSubpacketGeneratorWrapper setKeyExpirationTime(@Nullable KeyExpirationTime keyExpirationTime);

    SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(Set<CompressionAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(boolean isCritical, Set<CompressionAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredCompressionAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm... algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(Set<SymmetricKeyAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(boolean isCritical, Set<SymmetricKeyAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredSymmetricKeyAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(HashAlgorithm... algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(Set<HashAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(boolean isCritical, Set<HashAlgorithm> algorithms);

    SignatureSubpacketGeneratorWrapper setPreferredHashAlgorithms(@Nullable PreferredAlgorithms algorithms);

    SignatureSubpacketGeneratorWrapper addRevocationKey(@Nonnull PGPPublicKey revocationKey);

    SignatureSubpacketGeneratorWrapper addRevocationKey(boolean isCritical, @Nonnull PGPPublicKey revocationKey);

    SignatureSubpacketGeneratorWrapper addRevocationKey(boolean isCritical, boolean isSensitive, @Nonnull PGPPublicKey revocationKey);

    SignatureSubpacketGeneratorWrapper addRevocationKey(@Nonnull RevocationKey revocationKey);

    SignatureSubpacketGeneratorWrapper clearRevocationKeys();

    SignatureSubpacketGeneratorWrapper setFeatures(Feature... features);

    SignatureSubpacketGeneratorWrapper setFeatures(boolean isCritical, Feature... features);

    SignatureSubpacketGeneratorWrapper setFeatures(@Nullable Features features);
}
