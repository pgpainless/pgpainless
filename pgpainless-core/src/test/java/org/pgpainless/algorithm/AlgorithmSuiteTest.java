/*
 * Copyright 2021 Paul Schaub.
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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AlgorithmSuiteTest {

    private AlgorithmSuite suite;

    @BeforeEach
    public void resetEmptyAlgorithmSuite() {
        suite = new AlgorithmSuite(
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList()
        );
    }

    @Test
    public void setSymmetricAlgorithmsTest() {
        List<SymmetricKeyAlgorithm> algorithmList = Arrays.asList(
                SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_256
        );

        suite.setSymmetricKeyAlgorithms(algorithmList);

        assertEquals(algorithmList, new ArrayList<>(suite.getSymmetricKeyAlgorithms()));
    }

    @Test
    public void setHashAlgorithmsTest() {
        List<HashAlgorithm> algorithmList = Arrays.asList(
                HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512
        );

        suite.setHashAlgorithms(algorithmList);

        assertEquals(algorithmList, new ArrayList<>(suite.getHashAlgorithms()));
    }

    @Test
    public void setCompressionAlgorithmsTest() {
        List<CompressionAlgorithm> algorithmList = Arrays.asList(
                CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.BZIP2
        );

        suite.setCompressionAlgorithms(algorithmList);

        assertEquals(algorithmList, new ArrayList<>(suite.getCompressionAlgorithms()));
    }
}
