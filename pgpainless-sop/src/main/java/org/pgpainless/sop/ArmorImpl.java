// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.decryption_verification.OpenPgpInputStream;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

/**
 * Implementation of the <pre>armor</pre> operation using PGPainless.
 */
public class ArmorImpl implements Armor {

    @Override
    public Armor label(ArmorLabel label) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption("Setting custom Armor labels not supported.");
    }

    @Override
    public Ready data(InputStream data) throws SOPGPException.BadData {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                // By buffering the output stream, we can improve performance drastically
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream);

                // Determine nature of the given data
                OpenPgpInputStream openPgpIn = new OpenPgpInputStream(data);
                openPgpIn.reset();

                if (openPgpIn.isAsciiArmored()) {
                    // armoring already-armored data is an idempotent operation
                    Streams.pipeAll(openPgpIn, bufferedOutputStream);
                    bufferedOutputStream.flush();
                    openPgpIn.close();
                    return;
                }

                ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bufferedOutputStream);
                Streams.pipeAll(openPgpIn, armor);
                bufferedOutputStream.flush();
                armor.close();
            }
        };
    }
}
