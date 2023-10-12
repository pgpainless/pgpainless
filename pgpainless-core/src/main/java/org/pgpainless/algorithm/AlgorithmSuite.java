// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The {@link AlgorithmSuite} class is consulted when new OpenPGP keys are being generated to set
 * preferred algorithms on the key.
 */
public class AlgorithmSuite {

    private static final List<SymmetricKeyAlgorithm> defaultSymmetricAlgorithms = Arrays.asList(
            SymmetricKeyAlgorithm.AES_256,
            SymmetricKeyAlgorithm.AES_192,
            SymmetricKeyAlgorithm.AES_128);
    private static final List<HashAlgorithm> defaultHashAlgorithms = Arrays.asList(
            HashAlgorithm.SHA512,
            HashAlgorithm.SHA384,
            HashAlgorithm.SHA256,
            HashAlgorithm.SHA224);
    private static final List<CompressionAlgorithm> defaultCompressionAlgorithms = Arrays.asList(
            CompressionAlgorithm.ZLIB,
            CompressionAlgorithm.BZIP2,
            CompressionAlgorithm.ZIP,
            CompressionAlgorithm.UNCOMPRESSED);
    private static final List<AEADAlgorithmCombination> defaultAEADAlgorithms = Arrays.asList(
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_256, AEADAlgorithm.OCB),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_256, AEADAlgorithm.EAX),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_256, AEADAlgorithm.GCM),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_192, AEADAlgorithm.OCB),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_192, AEADAlgorithm.EAX),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_192, AEADAlgorithm.GCM),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_128, AEADAlgorithm.OCB),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_128, AEADAlgorithm.EAX),
            AEADAlgorithmCombination.from(SymmetricKeyAlgorithm.AES_128, AEADAlgorithm.GCM));
    private static final AlgorithmSuite defaultAlgorithmSuite = new AlgorithmSuite(
            defaultSymmetricAlgorithms,
            defaultHashAlgorithms,
            defaultCompressionAlgorithms,
            defaultAEADAlgorithms);

    private final Set<SymmetricKeyAlgorithm> symmetricKeyAlgorithms;
    private final Set<HashAlgorithm> hashAlgorithms;
    private final Set<CompressionAlgorithm> compressionAlgorithms;
    private final Set<AEADAlgorithmCombination> aeadAlgorithms;

    /**
     * Create a new AlgorithmSuite.
     *
     * @deprecated use {@link AlgorithmSuite#AlgorithmSuite(List, List, List, List)} instead.
     * @param symmetricKeyAlgorithms preferred symmetric algorithms
     * @param hashAlgorithms preferred hash algorithms
     * @param compressionAlgorithms preferred compression algorithms
     */
    @Deprecated
    public AlgorithmSuite(@Nonnull List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          @Nonnull List<HashAlgorithm> hashAlgorithms,
                          @Nonnull List<CompressionAlgorithm> compressionAlgorithms) {
        this(symmetricKeyAlgorithms, hashAlgorithms, compressionAlgorithms, defaultAEADAlgorithms);
    }

    /**
     * Create a new AlgorithmSuite.
     * @param symmetricKeyAlgorithms preferred symmetric algorithms
     * @param hashAlgorithms preferred hash algorithms
     * @param compressionAlgorithms preferred compression algorithms
     * @param aeadAlgorithms preferred AEAD algorithm combinations
     */
    public AlgorithmSuite(@Nonnull List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          @Nonnull List<HashAlgorithm> hashAlgorithms,
                          @Nonnull List<CompressionAlgorithm> compressionAlgorithms,
                          @Nonnull List<AEADAlgorithmCombination> aeadAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(symmetricKeyAlgorithms));
        this.hashAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(hashAlgorithms));
        this.compressionAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(compressionAlgorithms));
        this.aeadAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(aeadAlgorithms));
    }

    public Set<SymmetricKeyAlgorithm> getSymmetricKeyAlgorithms() {
        return new LinkedHashSet<>(symmetricKeyAlgorithms);
    }

    public Set<HashAlgorithm> getHashAlgorithms() {
        return new LinkedHashSet<>(hashAlgorithms);
    }

    public Set<CompressionAlgorithm> getCompressionAlgorithms() {
        return new LinkedHashSet<>(compressionAlgorithms);
    }

    public Set<AEADAlgorithmCombination> getAEADAlgorithms() {
        return new LinkedHashSet<>(aeadAlgorithms);
    }

    public static AlgorithmSuite getDefaultAlgorithmSuite() {
        return defaultAlgorithmSuite;
    }

}
