// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.io.InputStream;

class KeyReader {

    static PGPSecretKeyRingCollection readSecretKeys(InputStream keyInputStream, boolean requireContent)
            throws IOException, SOPGPException.BadData {
        PGPSecretKeyRingCollection keys;
        try {
            keys = PGPainless.readKeyRing().secretKeyRingCollection(keyInputStream);
        } catch (IOException e) {
            String message = e.getMessage();
            if (message == null) {
                throw e;
            }
            if (message.startsWith("unknown object in stream:") ||
                    message.startsWith("invalid header encountered")) {
                throw new SOPGPException.BadData(e);
            }
            throw e;
        } catch (PGPException e) {
            throw new SOPGPException.BadData("Cannot read keys.", e);
        }

        if (requireContent && (keys == null || keys.size() == 0)) {
            throw new SOPGPException.BadData(new PGPException("No key data found."));
        }

        return keys;
    }

    static PGPPublicKeyRingCollection readPublicKeys(InputStream certIn, boolean requireContent)
            throws IOException {
        PGPPublicKeyRingCollection certs;
        try {
            certs = PGPainless.readKeyRing().publicKeyRingCollection(certIn);
        } catch (IOException e) {
            if (e.getMessage() != null && e.getMessage().startsWith("unknown object in stream:")) {
                throw new SOPGPException.BadData(e);
            }
            throw e;
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        if (requireContent && (certs == null || certs.size() == 0)) {
            throw new SOPGPException.BadData(new PGPException("No cert data found."));
        }
        return certs;
    }
}
