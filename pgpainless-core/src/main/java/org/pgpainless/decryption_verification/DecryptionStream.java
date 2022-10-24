// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import javax.annotation.Nonnull;

public abstract class DecryptionStream extends CloseForResultInputStream {
    public DecryptionStream(@Nonnull OpenPgpMetadata.Builder resultBuilder) {
        super(resultBuilder);
    }
}
