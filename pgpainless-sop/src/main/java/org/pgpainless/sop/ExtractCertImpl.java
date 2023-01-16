// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.util.ArmorUtils;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.ExtractCert;

/**
 * Implementation of the <pre>extract-cert</pre> operation using PGPainless.
 */
public class ExtractCertImpl implements ExtractCert {

    private boolean armor = true;

    @Override
    public ExtractCert noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData {
        PGPSecretKeyRingCollection keys = KeyReader.readSecretKeys(keyInputStream, true);

        List<PGPPublicKeyRing> certs = new ArrayList<>();
        for (PGPSecretKeyRing key : keys) {
            PGPPublicKeyRing cert = PGPainless.extractCertificate(key);
            certs.add(cert);
        }

        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {

                for (PGPPublicKeyRing cert : certs) {
                    OutputStream out = armor ? ArmorUtils.toAsciiArmoredStream(cert, outputStream) : outputStream;
                    cert.encode(out);

                    if (armor) {
                        out.close();
                    }
                }
            }
        };
    }
}
