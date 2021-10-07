// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
