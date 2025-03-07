// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation;
import org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPImplementation;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;

/**
 * InvocationContextProvider that sets different {@link org.bouncycastle.openpgp.api.OpenPGPImplementation}
 * before running annotated tests.
 *
 * Example test annotation:
 * {@code
 *     @TestTemplate
 *     @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
 *     public void testAllImplementationFactories() {
 *         ...
 *     }
 * }
 *
 * @see <a href="https://www.baeldung.com/junit5-test-templates">Baeldung: Writing Templates for Test Cases Using JUnit 5</a>
 */
public class TestAllImplementations implements TestTemplateInvocationContextProvider {

    private static final List<OpenPGPImplementation> IMPLEMENTATIONS = Arrays.asList(
            new BcOpenPGPImplementation(),
            new JcaOpenPGPImplementation()
    );

    @Override
    public boolean supportsTestTemplate(ExtensionContext context) {
        return true;
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(ExtensionContext context) {

        return IMPLEMENTATIONS.stream()
                .map(implementation -> new TestTemplateInvocationContext() {
                    @Override
                    public String getDisplayName(int invocationIndex) {
                        return context.getDisplayName() + " with " + implementation.getClass().getSimpleName();
                    }

                    @Override
                    public List<Extension> getAdditionalExtensions() {
                        return Collections.singletonList(
                                (BeforeTestExecutionCallback) ctx -> OpenPGPImplementation.setInstance(implementation)
                        );
                    }
                });
    }
}
