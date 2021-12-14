// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.pgpainless.implementation.BcImplementationFactory;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.implementation.JceImplementationFactory;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

/**
 * Utility class used to provide all available implementations of {@link ImplementationFactory} for parametrized tests.
 *
 * @deprecated in favor of {@link ImplementationFactoryTestInvocationContextProvider}.
 */
public class TestImplementationFactoryProvider implements ArgumentsProvider {

    private static final List<ImplementationFactory> IMPLEMENTATIONS = Arrays.asList(
            new BcImplementationFactory(),
            new JceImplementationFactory()
    );

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        return IMPLEMENTATIONS.stream().map(Arguments::of);
    }
}
