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
import java.util.List;

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

    private List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms;
    private List<HashAlgorithm> hashAlgorithms;
    private List<CompressionAlgorithm> compressionAlgorithms;

    public AlgorithmSuite(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms,
                          List<HashAlgorithm> hashAlgorithms,
                          List<CompressionAlgorithm> compressionAlgorithms) {
        this.symmetricKeyAlgorithms = Collections.unmodifiableList(symmetricKeyAlgorithms);
        this.hashAlgorithms = Collections.unmodifiableList(hashAlgorithms);
        this.compressionAlgorithms = Collections.unmodifiableList(compressionAlgorithms);
    }

    public void setSymmetricKeyAlgorithms(List<SymmetricKeyAlgorithm> symmetricKeyAlgorithms) {
        this.symmetricKeyAlgorithms = symmetricKeyAlgorithms;
    }

    public List<SymmetricKeyAlgorithm> getSymmetricKeyAlgorithms() {
        return new ArrayList<>(symmetricKeyAlgorithms);
    }

    public int[] getSymmetricKeyAlgorithmIds() {
        int[] array = new int[symmetricKeyAlgorithms.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = symmetricKeyAlgorithms.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setHashAlgorithms(List<HashAlgorithm> hashAlgorithms) {
        this.hashAlgorithms = hashAlgorithms;
    }

    public List<HashAlgorithm> getHashAlgorithms() {
        return hashAlgorithms;
    }

    public int[] getHashAlgorithmIds() {
        int[] array = new int[hashAlgorithms.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = hashAlgorithms.get(i).getAlgorithmId();
        }
        return array;
    }

    public void setCompressionAlgorithms(List<CompressionAlgorithm> compressionAlgorithms) {
        this.compressionAlgorithms = compressionAlgorithms;
    }

    public List<CompressionAlgorithm> getCompressionAlgorithms() {
        return compressionAlgorithms;
    }

    public int[] getCompressionAlgorithmIds() {
        int[] array = new int[compressionAlgorithms.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = compressionAlgorithms.get(i).getAlgorithmId();
        }
        return array;
    }

    public static AlgorithmSuite getDefaultAlgorithmSuite() {
        return defaultAlgorithmSuite;
    }
}
