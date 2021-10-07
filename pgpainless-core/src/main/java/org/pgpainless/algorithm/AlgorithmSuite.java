// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

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

    private static AlgorithmSuite defaultAlgorithmSuite = new AlgorithmSuite(
            Arrays.asList(
                    SymmetricKeyAlgorithm.AES_256,
                    SymmetricKeyAlgorithm.AES_192,
                    SymmetricKeyAlgorithm.AES_128),
            Arrays.asList(
                    HashAlgorithm.SHA512,
                    HashAlgorithm.SHA384,
                    HashAlgorithm.SHA256,
                    HashAlgorithm.SHA224),
            Arrays.asList(
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZIP2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.UNCOMPRESSED)
    );

    private final Set<SymmetricKeyAlgorithm> symmetricKeyAlgorithms;
    private final Set<HashAlgorithm> hashAlgorithms;
    private final Set<CompressionAlgorithm> compressionAlgorithms;

    public AlgorithmSuite(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          List<HashAlgorithm> hashAlgorithms,
                          List<CompressionAlgorithm> compressionAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(symmetricKeyAlgorithms));
        this.hashAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(hashAlgorithms));
        this.compressionAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(compressionAlgorithms));
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

    public static AlgorithmSuite getDefaultAlgorithmSuite() {
        return defaultAlgorithmSuite;
    }
}
