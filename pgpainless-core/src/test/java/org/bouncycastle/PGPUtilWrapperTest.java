// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ImplementationFactoryTestInvocationContextProvider;
import org.pgpainless.util.PGPUtilWrapper;

public class PGPUtilWrapperTest {

    @TestTemplate
    @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
    public void testGetDecoderStream() throws IOException {

        ByteArrayInputStream msg = new ByteArrayInputStream("Foo\nBar".getBytes(StandardCharsets.UTF_8));
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream litOut = literalDataGenerator.open(out, PGPLiteralDataGenerator.TEXT, "", new Date(), new byte[1 << 9]);
        Streams.pipeAll(msg, litOut);
        literalDataGenerator.close();

        InputStream in = new ByteArrayInputStream(out.toByteArray());
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(in);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
        InputStream litIn = literalData.getDataStream();
        BufferedInputStream bufIn = new BufferedInputStream(litIn);
        InputStream decoderStream = PGPUtilWrapper.getDecoderStream(bufIn);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        Streams.pipeAll(decoderStream, result);
        assertEquals("Foo\nBar", result.toString());
    }
}
