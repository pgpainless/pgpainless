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
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.key.OpenPgpV4Fingerprint;

public class ArmorUtils {

    public static String toAsciiArmoredString(PGPSecretKeyRing secretKeys) throws IOException {
        MultiMap<String, String> header = keyToHeader(secretKeys);
        return toAsciiArmoredString(secretKeys.getEncoded(), header);
    }

    public static String toAsciiArmoredString(PGPPublicKeyRing publicKeys) throws IOException {
        MultiMap<String, String> header = keyToHeader(publicKeys);
        return toAsciiArmoredString(publicKeys.getEncoded(), header);
    }

    private static MultiMap<String, String> keyToHeader(PGPKeyRing keyRing) {
        MultiMap<String, String> header = new MultiMap<>();
        OpenPgpV4Fingerprint fingerprint = new OpenPgpV4Fingerprint(keyRing);
        Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();

        header.put("Comment", fingerprint.prettyPrint());
        if (userIds.hasNext()) {
            header.put("Comment", userIds.next());
        }
        return header;
    }

    public static String toAsciiArmoredString(byte[] bytes) throws IOException {
        return toAsciiArmoredString(bytes, null);
    }

    public static String toAsciiArmoredString(byte[] bytes, MultiMap<String, String> additionalHeaderValues) throws IOException {
        return toAsciiArmoredString(new ByteArrayInputStream(bytes), additionalHeaderValues);
    }

    public static String toAsciiArmoredString(InputStream inputStream) throws IOException {
        return toAsciiArmoredString(inputStream, null);
    }

    public static String toAsciiArmoredString(InputStream inputStream, MultiMap<String, String> additionalHeaderValues) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(out);
        if (additionalHeaderValues != null) {
            for (String header : additionalHeaderValues.keySet()) {
                for (String value : additionalHeaderValues.get(header)) {
                    armor.addHeader(header, value);
                }
            }
        }
        Streams.pipeAll(inputStream, armor);
        armor.close();

        return out.toString();
    }
}
