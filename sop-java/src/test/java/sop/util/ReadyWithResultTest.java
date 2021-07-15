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
package sop.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.ReadyWithResult;
import sop.Verification;
import sop.exception.SOPGPException;

public class ReadyWithResultTest {

    @Test
    public void testReadyWithResult() throws SOPGPException.NoSignature, IOException {
        byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        List<Verification> result = Collections.singletonList(
                new Verification(UTCUtil.parseUTCDate("2019-10-24T23:48:29Z"),
                        "C90E6D36200A1B922A1509E77618196529AE5FF8",
                        "C4BC2DDB38CCE96485EBE9C2F20691179038E5C6")
        );
        ReadyWithResult<List<Verification>> readyWithResult = new ReadyWithResult<List<Verification>>() {
            @Override
            public List<Verification> writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                outputStream.write(data);
                return result;
            }
        };

        ByteArrayAndResult<List<Verification>> bytesAndResult = readyWithResult.toBytes();
        assertArrayEquals(data, bytesAndResult.getBytes());
        assertEquals(result, bytesAndResult.getResult());
    }
}
