// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.Ready;
import sop.enums.SignAs;
import sop.exception.SOPGPException;
import sop.operation.Sign;

public class SignImpl implements Sign {

    private boolean armor = true;
    private SignAs mode = SignAs.Binary;
    private final SigningOptions signingOptions = new SigningOptions();

    @Override
    public Sign noArmor() {
        armor = false;
        return this;
    }

    @Override
    public Sign mode(SignAs mode) {
        this.mode = mode;
        return this;
    }

    @Override
    public Sign key(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException {
        try {
            PGPSecretKeyRingCollection keys = PGPainless.readKeyRing().secretKeyRingCollection(keyIn);
            if (keys.size() != 1) {
                throw new SOPGPException.BadData(new AssertionError("Exactly one secret key at a time expected. Got " + keys.size()));
            }

            PGPSecretKeyRing key = keys.iterator().next();
            KeyRingInfo info = new KeyRingInfo(key);
            if (!info.isFullyDecrypted()) {
                throw new SOPGPException.KeyIsProtected();
            }
            signingOptions.addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), key, modeToSigType(mode));
        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Ready data(InputStream data) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(buffer)
                    .withOptions(ProducerOptions.sign(signingOptions)
                            .setAsciiArmor(armor));

            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {

                    if (signingStream.isClosed()) {
                        throw new IllegalStateException("EncryptionStream is already closed.");
                    }

                    Streams.pipeAll(data, signingStream);
                    signingStream.close();
                    EncryptionResult encryptionResult = signingStream.getResult();

                    List<PGPSignature> signatures = new ArrayList<>();
                    for (SubkeyIdentifier key : encryptionResult.getDetachedSignatures().keySet()) {
                        signatures.addAll(encryptionResult.getDetachedSignatures().get(key));
                    }

                    OutputStream out;
                    if (armor) {
                        out = ArmoredOutputStreamFactory.get(outputStream);
                    } else {
                        out = outputStream;
                    }
                    for (PGPSignature sig : signatures) {
                        sig.encode(out);
                    }
                    out.close();
                    outputStream.close(); // armor out does not close underlying stream
                }
            };

        } catch (PGPException e) {
            throw new RuntimeException(e);
        }

    }

    private static DocumentSignatureType modeToSigType(SignAs mode) {
        return mode == SignAs.Binary ? DocumentSignatureType.BINARY_DOCUMENT
                : DocumentSignatureType.CANONICAL_TEXT_DOCUMENT;
    }
}
