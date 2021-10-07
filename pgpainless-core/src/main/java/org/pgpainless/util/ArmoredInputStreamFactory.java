// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;

public final class ArmoredInputStreamFactory {

    private ArmoredInputStreamFactory() {

    }

    public static ArmoredInputStream get(InputStream inputStream) throws IOException {
        if (inputStream instanceof CRCingArmoredInputStreamWrapper) {
            return (ArmoredInputStream) inputStream;
        }
        if (inputStream instanceof ArmoredInputStream) {
            return new CRCingArmoredInputStreamWrapper((ArmoredInputStream) inputStream);
        }

        ArmoredInputStream armorIn = new ArmoredInputStream(inputStream);
        return new CRCingArmoredInputStreamWrapper(armorIn);
    }
}
