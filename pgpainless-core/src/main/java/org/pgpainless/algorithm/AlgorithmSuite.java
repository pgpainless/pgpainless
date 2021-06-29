/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.algorithm;

import java.util.ArrayList;
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

    private Set<SymmetricKeyAlgorithm> symmetricKeyAlgorithms;
    private Set<HashAlgorithm> hashAlgorithms;
    private Set<CompressionAlgorithm> compressionAlgorithms;

    public AlgorithmSuite(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          List<HashAlgorithm> hashAlgorithms,
                          List<CompressionAlgorithm> compressionAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(symmetricKeyAlgorithms));
        this.hashAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(hashAlgorithms));
        this.compressionAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(compressionAlgorithms));
    }

    public void setSymmetricKeyAlgorithms(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(symmetricKeyAlgorithms));
    }

    public Set<SymmetricKeyAlgorithm> getSymmetricKeyAlgorithms() {
        return new LinkedHashSet<>(symmetricKeyAlgorithms);
    }

    public int[] getSymmetricKeyAlgorithmIds() {
        int[] array = new int[symmetricKeyAlgorithms.size()];
        List<SymmetricKeyAlgorithm> list = new ArrayList<>(getSymmetricKeyAlgorithms());
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setHashAlgorithms(List<HashAlgorithm> hashAlgorithms) {
        this.hashAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(hashAlgorithms));
    }

    public Set<HashAlgorithm> getHashAlgorithms() {
        return new LinkedHashSet<>(hashAlgorithms);
    }

    public int[] getHashAlgorithmIds() {
        int[] array = new int[hashAlgorithms.size()];
        List<HashAlgorithm> list = new ArrayList<>(getHashAlgorithms());
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setCompressionAlgorithms(List<CompressionAlgorithm> compressionAlgorithms) {
        this.compressionAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(compressionAlgorithms));
    }

    public Set<CompressionAlgorithm> getCompressionAlgorithms() {
        return new LinkedHashSet<>(compressionAlgorithms);
    }

    public int[] getCompressionAlgorithmIds() {
        int[] array = new int[compressionAlgorithms.size()];
        List<CompressionAlgorithm> list = new ArrayList<>(getCompressionAlgorithms());
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i).getAlgorithmId();
        }
        return array;
    }

    public static AlgorithmSuite getDefaultAlgorithmSuite() {
        return defaultAlgorithmSuite;
    }
}
