// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.PGPainless;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateReaderBackend;

public class CertificateReader implements CertificateReaderBackend {

    @Override
    public Certificate readCertificate(InputStream inputStream) throws IOException {
        final PGPPublicKeyRing certificate = PGPainless.readKeyRing().publicKeyRing(inputStream);
        return CertificateFactory.certificateFromPublicKeyRing(certificate);
    }
}
