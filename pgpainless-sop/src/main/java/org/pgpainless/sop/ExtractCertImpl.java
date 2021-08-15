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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmorUtils;
import sop.operation.ExtractCert;
import sop.Ready;
import sop.exception.SOPGPException;

public class ExtractCertImpl implements ExtractCert {

    private boolean armor = true;

    @Override
    public ExtractCert noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(keyInputStream);
        if (key == null) {
            throw new SOPGPException.BadData(new PGPException("No key data found."));
        }

        PGPPublicKeyRing cert = KeyRingUtils.publicKeyRingFrom(key);

        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                OutputStream out = armor ? ArmorUtils.createArmoredOutputStreamFor(cert, outputStream) : outputStream;
                cert.encode(out);

                if (armor) {
                    out.close();
                }
            }
        };
    }
}
