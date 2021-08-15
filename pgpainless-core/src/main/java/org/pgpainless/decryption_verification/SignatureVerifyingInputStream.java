/*
 * Copyright 2018 Paul Schaub.
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

import static org.pgpainless.signature.SignatureValidator.signatureIsEffective;
import static org.pgpainless.signature.SignatureValidator.signatureStructureIsAcceptable;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.Date;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.OnePassSignature;
import org.pgpainless.signature.SignatureChainValidator;
import org.pgpainless.exception.SignatureValidationException;

public class SignatureVerifyingInputStream extends FilterInputStream {

    private static final Logger LOGGER = Logger.getLogger(SignatureVerifyingInputStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private final PGPObjectFactory objectFactory;
    private final Map<OpenPgpV4Fingerprint, OnePassSignature> onePassSignatures;
    private final OpenPgpMetadata.Builder resultBuilder;

    private boolean validated = false;

    protected SignatureVerifyingInputStream(@Nonnull InputStream inputStream,
                                            @Nonnull PGPObjectFactory objectFactory,
                                            @Nonnull Map<OpenPgpV4Fingerprint, OnePassSignature> onePassSignatures,
                                            @Nonnull OpenPgpMetadata.Builder resultBuilder) {
        super(inputStream);
        this.objectFactory = objectFactory;
        this.resultBuilder = resultBuilder;
        this.onePassSignatures = onePassSignatures;

        LOGGER.log(LEVEL, "Begin verifying OnePassSignatures");
    }

    private void updateOnePassSignatures(byte data) {
        for (OnePassSignature signature : onePassSignatures.values()) {
            signature.getOnePassSignature().update(data);
        }
    }

    private void updateOnePassSignatures(byte[] b, int off, int len) {
        for (OnePassSignature signature : onePassSignatures.values()) {
            signature.getOnePassSignature().update(b, off, len);
        }
    }

    private void validateOnePassSignaturesIfNeeded() throws IOException {
        if (validated) {
            return;
        }
        validated = true;
        validateOnePassSignaturesIfAny();
    }

    private void validateOnePassSignaturesIfAny() throws IOException {
        if (onePassSignatures.isEmpty()) {
            LOGGER.log(LEVEL, "No One-Pass-Signatures found -> No validation");
            return;
        }
        validateOnePassSignatures();
    }

    private void validateOnePassSignatures() throws IOException {
        PGPSignatureList signatureList = findPgpSignatureList();

        try {
            for (PGPSignature signature : signatureList) {
                OpenPgpV4Fingerprint fingerprint = findFingerprintForSignature(signature);
                OnePassSignature onePassSignature = findOnePassSignature(fingerprint);
                if (onePassSignature == null) {
                    LOGGER.log(LEVEL, "Found Signature without respective OnePassSignature packet -> skip");
                    continue;
                }

                verifySignatureOrThrowSignatureException(signature, onePassSignature);
            }
        } catch (PGPException | SignatureException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    private void verifySignatureOrThrowSignatureException(PGPSignature signature, OnePassSignature onePassSignature)
            throws PGPException, SignatureException {
        Policy policy = PGPainless.getPolicy();
        try {
            PGPPublicKey signingKey = onePassSignature.getVerificationKeys().getPublicKey(signature.getKeyID());
            signatureStructureIsAcceptable(signingKey, policy).verify(signature);
            signatureIsEffective(new Date()).verify(signature);

            SignatureChainValidator.validateSigningKey(signature, onePassSignature.getVerificationKeys(), PGPainless.getPolicy());

        } catch (SignatureValidationException e) {
            throw new SignatureException("Signature key is not valid.", e);
        }
        if (!onePassSignature.verify(signature)) {
            throw new SignatureException("Bad Signature of key " + signature.getKeyID());
        } else {
            LOGGER.log(LEVEL, "Verified signature of key {}", Long.toHexString(signature.getKeyID()));
        }
    }

    private OnePassSignature findOnePassSignature(OpenPgpV4Fingerprint fingerprint) {
        if (fingerprint != null) {
            return onePassSignatures.get(fingerprint);
        }
        return null;
    }

    private PGPSignatureList findPgpSignatureList() throws IOException {
        PGPSignatureList signatureList = null;
        Object pgpObject = objectFactory.nextObject();
        while (pgpObject !=  null && signatureList == null) {
            if (pgpObject instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) pgpObject;
            } else {
                pgpObject = objectFactory.nextObject();
            }
        }

        if (signatureList == null || signatureList.isEmpty()) {
            throw new IOException("Verification failed - No Signatures found");
        }

        return signatureList;
    }

    private OpenPgpV4Fingerprint findFingerprintForSignature(PGPSignature signature) {
        OpenPgpV4Fingerprint fingerprint = null;
        for (OpenPgpV4Fingerprint f : onePassSignatures.keySet()) {
            if (f.getKeyId() == signature.getKeyID()) {
                fingerprint = f;
                break;
            }
        }
        return fingerprint;
    }

    @Override
    public int read() throws IOException {
        final int data = super.read();
        final boolean endOfStream = data == -1;
        if (endOfStream) {
            validateOnePassSignaturesIfNeeded();
        } else {
            updateOnePassSignatures((byte) data);
        }
        return data;
    }

    @Override
    public int read(@Nonnull byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(@Nonnull byte[] b, int off, int len) throws IOException {
        int read = super.read(b, off, len);

        final boolean endOfStream = read == -1;
        if (endOfStream) {
            validateOnePassSignaturesIfNeeded();
        } else {
            updateOnePassSignatures(b, off, read);
        }
        return read;
    }

    @Override
    public long skip(long n) {
        throw new UnsupportedOperationException("skip() is not supported");
    }

    @Override
    public synchronized void mark(int readlimit) {
        throw new UnsupportedOperationException("mark() not supported");
    }

    @Override
    public synchronized void reset() {
        throw new UnsupportedOperationException("reset() is not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
