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

import static org.pgpainless.signature.SignatureValidator.verifySignatureCreationTimeIsInBounds;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
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
    private final ConsumerOptions options;
    private final OpenPgpMetadata.Builder resultBuilder;
    private boolean isClosed = false;
    private List<IntegrityProtectedInputStream> integrityProtectedInputStreamList;
    private final InputStream armorStream;

    DecryptionStream(@Nonnull InputStream wrapped, @Nonnull ConsumerOptions options,
                     @Nonnull OpenPgpMetadata.Builder resultBuilder,
                     List<IntegrityProtectedInputStream> integrityProtectedInputStreamList,
                     InputStream armorStream) {
        this.inputStream = wrapped;
        this.options = options;
        this.resultBuilder = resultBuilder;
        this.integrityProtectedInputStreamList = integrityProtectedInputStreamList;
        this.armorStream = armorStream;
    }

    @Override
    public int read() throws IOException {
        int r = inputStream.read();
        maybeUpdateDetachedSignatures(r);
        return r;
    }

    @Override
    public int read(@Nonnull byte[] bytes, int offset, int length) throws IOException {
        int read = inputStream.read(bytes, offset, length);
        if (read != -1) {
            maybeUpdateDetachedSignatures(bytes, offset, read);
        }
        return read;
    }

    private void maybeUpdateDetachedSignatures(byte[] bytes, int offset, int length) {
        for (DetachedSignature s : resultBuilder.getDetachedSignatures()) {
            s.getSignature().update(bytes, offset, length);
        }
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
        if (armorStream != null) {
            Streams.drain(armorStream);
        }
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
                verifySignatureCreationTimeIsInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter()).verify(s.getSignature());
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
