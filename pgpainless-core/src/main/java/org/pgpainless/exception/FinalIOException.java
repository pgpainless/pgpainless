// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import java.io.IOException;

/**
 * Wrapper for {@link IOException} indicating that we need to throw this exception up.
 */
public class FinalIOException extends IOException {

    public FinalIOException(IOException e) {
        super(e);
    }
}
