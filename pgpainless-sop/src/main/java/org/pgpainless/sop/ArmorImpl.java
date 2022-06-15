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
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

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
                ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bufferedOutputStream);
                Streams.pipeAll(data, armor);
                bufferedOutputStream.flush();
                armor.close();
            }
        };
    }
}
