/*
 * Copyright 2020 Paul Schaub.
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
import java.io.PushbackInputStream;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

public class ArmorImpl implements Armor {

    public static final byte[] ARMOR_START = "-----BEGIN PGP".getBytes(Charset.forName("UTF8"));

    boolean allowNested = false;

    @Override
    public Armor label(ArmorLabel label) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public Armor allowNested() throws SOPGPException.UnsupportedOption {
        allowNested = true;
        return this;
    }

    @Override
    public Ready data(InputStream data) throws SOPGPException.BadData {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                PushbackInputStream pbIn = new PushbackInputStream(data, ARMOR_START.length);
                byte[] buffer = new byte[ARMOR_START.length];
                int read = pbIn.read(buffer);
                pbIn.unread(buffer, 0, read);
                if (!allowNested && Arrays.equals(ARMOR_START, buffer)) {
                    Streams.pipeAll(pbIn, System.out);
                } else {
                    ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(System.out);
                    Streams.pipeAll(pbIn, armor);
                    armor.close();
                }
            }
        };
    }
}
