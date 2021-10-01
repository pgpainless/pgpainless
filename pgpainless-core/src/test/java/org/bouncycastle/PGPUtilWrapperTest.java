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
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.util.PGPUtilWrapper;

public class PGPUtilWrapperTest {

    @Test
    public void testGetDecoderStream() throws IOException {
        ByteArrayInputStream msg = new ByteArrayInputStream("Foo\nBar".getBytes(StandardCharsets.UTF_8));
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream litOut = literalDataGenerator.open(out, PGPLiteralDataGenerator.TEXT, "", new Date(), new byte[1 << 9]);
        Streams.pipeAll(msg, litOut);
        literalDataGenerator.close();

        InputStream in = new ByteArrayInputStream(out.toByteArray());
        PGPObjectFactory objectFactory = new BcPGPObjectFactory(in);
        PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();
        InputStream litIn = literalData.getDataStream();
        BufferedInputStream bufIn = new BufferedInputStream(litIn);
        InputStream decoderStream = PGPUtilWrapper.getDecoderStream(bufIn);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        Streams.pipeAll(decoderStream, result);
        assertEquals("Foo\nBar", result.toString());
    }
}
