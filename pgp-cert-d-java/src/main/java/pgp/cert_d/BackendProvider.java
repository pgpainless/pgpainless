// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.CertificateReaderBackend;
import pgp.certificate_store.MergeCallback;

public abstract class BackendProvider {

    public abstract CertificateReaderBackend provideCertificateReaderBackend();

    public abstract MergeCallback provideDefaultMergeCallback();

}
