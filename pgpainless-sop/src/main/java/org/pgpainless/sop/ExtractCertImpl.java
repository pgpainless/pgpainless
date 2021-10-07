// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
