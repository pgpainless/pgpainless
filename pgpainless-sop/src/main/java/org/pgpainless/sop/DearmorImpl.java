// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
