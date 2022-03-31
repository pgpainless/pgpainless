// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.pgpainless.key.SubkeyIdentifier;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;

class SignatureGenerationStream extends OutputStream {

    private final OutputStream wrapped;
    private final SigningOptions options;

    SignatureGenerationStream(OutputStream wrapped, SigningOptions signingOptions) {
        this.wrapped = wrapped;
        this.options = signingOptions;
    }

    @Override
    public void write(int b) throws IOException {
        wrapped.write(b);
        if (options == null || options.getSigningMethods().isEmpty()) {
            return;
        }

        for (SubkeyIdentifier signingKey : options.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = options.getSigningMethods().get(signingKey);
            PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
            byte asByte = (byte) (b & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(@Nonnull byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }

    @Override
    public void write(@Nonnull byte[] buffer, int off, int len) throws IOException {
        wrapped.write(buffer, 0, len);
        if (options == null || options.getSigningMethods().isEmpty()) {
            return;
        }
        for (SubkeyIdentifier signingKey : options.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = options.getSigningMethods().get(signingKey);
            PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void close() throws IOException {
        wrapped.close();
    }
}
