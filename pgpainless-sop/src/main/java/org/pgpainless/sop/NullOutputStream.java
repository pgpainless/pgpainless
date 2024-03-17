// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.OutputStream;

/**
 * {@link OutputStream} that simply discards bytes written to it.
 */
public class NullOutputStream extends OutputStream {
    @Override
    public void write(int b) {
        // NOP
    }
}
