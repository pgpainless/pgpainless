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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;
import sop.Ready;
import sop.operation.Dearmor;

public class DearmorImpl implements Dearmor {

    @Override
    public Ready data(InputStream data) throws IOException {
        InputStream decoder = PGPUtil.getDecoderStream(data);
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                Streams.pipeAll(decoder, outputStream);
                decoder.close();
            }
        };
    }
}
