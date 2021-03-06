/*
 * Copyright 2018-2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.signature.DetachedSignature;
import org.pgpainless.signature.SignatureChainValidator;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.util.IntegrityProtectedInputStream;

/**
 * Decryption Stream that handles updating and verification of detached signatures,
 * as well as verification of integrity-protected input streams once the stream gets closed.
 */
public class DecryptionStream extends InputStream {

    private static final Logger LOGGER = Logger.getLogger(DecryptionStream.class.getName());

    private final InputStream inputStream;
    private final OpenPgpMetadata.Builder resultBuilder;
    private boolean isClosed = false;
    private List<IntegrityProtectedInputStream> integrityProtectedInputStreamList;

    DecryptionStream(@Nonnull InputStream wrapped, @Nonnull OpenPgpMetadata.Builder resultBuilder,
                     List<IntegrityProtectedInputStream> integrityProtectedInputStreamList) {
        this.inputStream = wrapped;
        this.resultBuilder = resultBuilder;
        this.integrityProtectedInputStreamList = integrityProtectedInputStreamList;
    }

    @Override
    public int read() throws IOException {
        int r = inputStream.read();
        maybeUpdateDetachedSignatures(r);
        return r;
    }

    private void maybeUpdateDetachedSignatures(int rByte) {
        for (DetachedSignature s : resultBuilder.getDetachedSignatures()) {
            if (rByte != -1) {
                s.getSignature().update((byte) rByte);
            }
        }
    }

    @Override
    public void close() throws IOException {
        inputStream.close();
        maybeVerifyDetachedSignatures();
        for (IntegrityProtectedInputStream s : integrityProtectedInputStreamList) {
            s.close();
        }
        this.isClosed = true;
    }

    private void maybeVerifyDetachedSignatures() {
        for (DetachedSignature s : resultBuilder.getDetachedSignatures()) {
            try {
                boolean verified = SignatureChainValidator.validateSignature(s.getSignature(), (PGPPublicKeyRing) s.getSigningKeyRing(), PGPainless.getPolicy());
                s.setVerified(verified);
            } catch (SignatureValidationException e) {
                LOGGER.log(Level.WARNING, "Could not verify signature of key " + s.getSigningKeyIdentifier(), e);
            }
        }
    }

    /**
     * Return the result of the decryption.
     * The result contains metadata about the decryption, such as signatures, used keys and algorithms, as well as information
     * about the decrypted file/stream.
     *
     * Can only be obtained once the stream got successfully closed ({@link #close()}).
     * @return metadata
     */
    public OpenPgpMetadata getResult() {
        if (!isClosed) {
            throw new IllegalStateException("DecryptionStream MUST be closed before the result can be accessed.");
        }
        return resultBuilder.build();
    }
}
