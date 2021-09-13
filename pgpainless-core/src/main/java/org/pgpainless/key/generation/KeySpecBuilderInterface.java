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
package org.pgpainless.key.generation;

import javax.annotation.Nonnull;

import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public interface KeySpecBuilderInterface {

    KeySpecBuilder overridePreferredCompressionAlgorithms(@Nonnull CompressionAlgorithm... compressionAlgorithms);

    KeySpecBuilder overridePreferredHashAlgorithms(@Nonnull HashAlgorithm... preferredHashAlgorithms);

    KeySpecBuilder overridePreferredSymmetricKeyAlgorithms(@Nonnull SymmetricKeyAlgorithm... preferredSymmetricKeyAlgorithms);

    KeySpec build();
}
