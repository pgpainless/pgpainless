// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.annotation.Nonnull;

import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class KeySpecBuilder implements KeySpecBuilderInterface {

    private final KeyType type;
    private final KeyFlag[] keyFlags;
    private final SelfSignatureSubpackets hashedSubpackets = new SignatureSubpackets();
    private final AlgorithmSuite algorithmSuite = PGPainless.getPolicy().getKeyGenerationAlgorithmSuite();
    private Set<CompressionAlgorithm> preferredCompressionAlgorithms = algorithmSuite.getCompressionAlgorithms();
    private Set<HashAlgorithm> preferredHashAlgorithms = algorithmSuite.getHashAlgorithms();
    private Set<SymmetricKeyAlgorithm> preferredSymmetricAlgorithms = algorithmSuite.getSymmetricKeyAlgorithms();
    private Date keyCreationDate;

    KeySpecBuilder(@Nonnull KeyType type, KeyFlag... flags) {
        if (flags == null) {
            this.keyFlags = new KeyFlag[0];
        } else {
            SignatureSubpacketsUtil.assureKeyCanCarryFlags(type, flags);
            this.keyFlags = flags;
        }
        this.type = type;
    }

    @Override
    public KeySpecBuilder overridePreferredCompressionAlgorithms(
            @Nonnull CompressionAlgorithm... compressionAlgorithms) {
        this.preferredCompressionAlgorithms = new LinkedHashSet<>(Arrays.asList(compressionAlgorithms));
        return this;
    }

    @Override
    public KeySpecBuilder overridePreferredHashAlgorithms(
            @Nonnull HashAlgorithm... preferredHashAlgorithms) {
        this.preferredHashAlgorithms = new LinkedHashSet<>(Arrays.asList(preferredHashAlgorithms));
        return this;
    }

    @Override
    public KeySpecBuilder overridePreferredSymmetricKeyAlgorithms(
            @Nonnull SymmetricKeyAlgorithm... preferredSymmetricKeyAlgorithms) {
        for (SymmetricKeyAlgorithm algo : preferredSymmetricKeyAlgorithms) {
            if (algo == SymmetricKeyAlgorithm.NULL) {
                throw new IllegalArgumentException("NULL (unencrypted) is an invalid symmetric key algorithm preference.");
            }
        }
        this.preferredSymmetricAlgorithms = new LinkedHashSet<>(Arrays.asList(preferredSymmetricKeyAlgorithms));
        return this;
    }

    @Override
    public KeySpecBuilder setKeyCreationDate(@Nonnull Date creationDate) {
        this.keyCreationDate = creationDate;
        return this;
    }

    @Override
    public KeySpec build() {
        this.hashedSubpackets.setKeyFlags(keyFlags);
        this.hashedSubpackets.setPreferredCompressionAlgorithms(preferredCompressionAlgorithms);
        this.hashedSubpackets.setPreferredHashAlgorithms(preferredHashAlgorithms);
        this.hashedSubpackets.setPreferredSymmetricKeyAlgorithms(preferredSymmetricAlgorithms);
        this.hashedSubpackets.setFeatures(Feature.MODIFICATION_DETECTION);

        return new KeySpec(type, (SignatureSubpackets) hashedSubpackets, false, keyCreationDate);
    }
}
