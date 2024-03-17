// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRingCollection;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Reader for OpenPGP keys and certificates with error matching according to the SOP spec.
 */
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
        }

        if (requireContent && keys.size() == 0) {
            throw new SOPGPException.BadData(new PGPException("No key data found."));
        }

        return keys;
    }

    static PGPPublicKeyRingCollection readPublicKeys(InputStream certIn, boolean requireContent)
            throws IOException {
        PGPKeyRingCollection certs;
        try {
            certs = PGPainless.readKeyRing().keyRingCollection(certIn, false);
        } catch (IOException e) {
            String msg = e.getMessage();
            if (msg != null && (msg.startsWith("unknown object in stream:") || msg.startsWith("invalid header encountered"))) {
                throw new SOPGPException.BadData(e);
            }
            throw e;
        } catch (PGPRuntimeOperationException e) {
            throw new SOPGPException.BadData(e);
        }
        if (certs.getPgpSecretKeyRingCollection().size() != 0) {
            throw new SOPGPException.BadData("Secret key components encountered, while certificates were expected.");
        }
        if (requireContent && certs.getPgpPublicKeyRingCollection().size() == 0) {
            throw new SOPGPException.BadData(new PGPException("No cert data found."));
        }
        return certs.getPgpPublicKeyRingCollection();
    }
}
