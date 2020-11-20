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
package org.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;

public class ArmorUtils {

    public static String toAsciiArmoredString(PGPSecretKeyRing secretKeys) throws IOException {
        return toAsciiArmoredString(secretKeys.getEncoded());
    }

    public static String toAsciiArmoredString(PGPPublicKeyRing publicKeys) throws IOException {
        return toAsciiArmoredString(publicKeys.getEncoded());
    }

    public static String toAsciiArmoredString(byte[] bytes) throws IOException {
        return toAsciiArmoredString(new ByteArrayInputStream(bytes));
    }

    public static String toAsciiArmoredString(InputStream inputStream) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(out);

        Streams.pipeAll(inputStream, armor);
        armor.close();

        return out.toString();
    }
}
