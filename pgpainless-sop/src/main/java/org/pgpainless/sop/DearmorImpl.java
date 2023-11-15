// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.Dearmor;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>dearmor</pre> operation using PGPainless.
 */
public class DearmorImpl implements Dearmor {

    @Nonnull
    @Override
    public Ready data(@Nonnull InputStream data) {
        InputStream decoder;
        try {
            decoder = PGPUtil.getDecoderStream(data);
        } catch (IOException e) {
            throw new SOPGPException.BadData(e);
        }
        return new Ready() {

            @Override
            public void writeTo(@Nonnull OutputStream outputStream) throws IOException {
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream);
                Streams.pipeAll(decoder, bufferedOutputStream);
                bufferedOutputStream.flush();
                decoder.close();
            }
        };
    }
}
