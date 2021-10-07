// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.pgpainless.implementation.BcImplementationFactory;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.implementation.JceImplementationFactory;

import java.util.Arrays;
import java.util.List;

/**
 * Utility class used to provide all available implementations of {@link ImplementationFactory} for parametrized tests.
 */
public class TestImplementationFactoryProvider {

    private static final List<ImplementationFactory> IMPLEMENTATIONS = Arrays.asList(
            new BcImplementationFactory(),
            new JceImplementationFactory()
    );

    public static List<ImplementationFactory> provideImplementationFactories() {
        return IMPLEMENTATIONS;
    }
}
