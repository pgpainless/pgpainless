// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.InputStream;

public abstract class DecryptionStream extends InputStream {

    public abstract MessageMetadata getMetadata();

    @Deprecated
    public OpenPgpMetadata getResult() {
        return getMetadata().toLegacyMetadata();
    }
}
