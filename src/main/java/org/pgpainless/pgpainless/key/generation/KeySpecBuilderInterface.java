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
package org.pgpainless.pgpainless.key.generation;

import org.pgpainless.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.pgpainless.algorithm.Feature;
import org.pgpainless.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.pgpainless.algorithm.KeyFlag;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;

public interface KeySpecBuilderInterface {

    WithDetailedConfiguration withKeyFlags(KeyFlag... flags);

    WithDetailedConfiguration withDefaultKeyFlags();

    KeySpec withInheritedSubPackets();

    interface WithDetailedConfiguration {

        WithPreferredSymmetricAlgorithms withDetailedConfiguration();

        KeySpec withDefaultAlgorithms();
    }

    interface WithPreferredSymmetricAlgorithms {

        WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(SymmetricKeyAlgorithm... algorithms);

        WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms();

        WithFeatures withDefaultAlgorithms();

    }

    interface WithPreferredHashAlgorithms {

        WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(HashAlgorithm... algorithms);

        WithPreferredCompressionAlgorithms withDefaultHashAlgorithms();

    }

    interface WithPreferredCompressionAlgorithms {

        WithFeatures withPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms);

        WithFeatures withDefaultCompressionAlgorithms();

    }

    interface WithFeatures {

        WithFeatures withFeature(Feature feature);

        KeySpec done();
    }

}
