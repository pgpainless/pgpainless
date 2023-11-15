// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import sop.ReadyWithResult;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.InlineVerify;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>inline-verify</pre> operation using PGPainless.
 */
public class InlineVerifyImpl implements InlineVerify {

    private final ConsumerOptions options = ConsumerOptions.get();

    @Override
    @Nonnull
    public InlineVerify notBefore(@Nonnull Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotBefore(timestamp);
        return this;
    }

    @Override
    @Nonnull
    public InlineVerify notAfter(@Nonnull Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotAfter(timestamp);
        return this;
    }

    @Override
    @Nonnull
    public InlineVerify cert(@Nonnull InputStream cert) throws SOPGPException.BadData, IOException {
        PGPPublicKeyRingCollection certificates = KeyReader.readPublicKeys(cert, true);
        options.addVerificationCerts(certificates);
        return this;
    }

    @Override
    @Nonnull
    public ReadyWithResult<List<Verification>> data(@Nonnull InputStream data) throws SOPGPException.NoSignature, SOPGPException.BadData {
        return new ReadyWithResult<List<Verification>>() {
            @Override
            public List<Verification> writeTo(@Nonnull OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                DecryptionStream decryptionStream;
                try {
                    decryptionStream = PGPainless.decryptAndOrVerify()
                            .onInputStream(data)
                            .withOptions(options);

                    Streams.pipeAll(decryptionStream, outputStream);
                    decryptionStream.close();

                    MessageMetadata metadata = decryptionStream.getMetadata();
                    List<Verification> verificationList = new ArrayList<>();

                    List<SignatureVerification> verifications = metadata.isUsingCleartextSignatureFramework() ?
                            metadata.getVerifiedDetachedSignatures() :
                            metadata.getVerifiedInlineSignatures();

                    for (SignatureVerification signatureVerification : verifications) {
                        verificationList.add(VerificationHelper.mapVerification(signatureVerification));
                    }

                    if (!options.getCertificateSource().getExplicitCertificates().isEmpty()) {
                        if (verificationList.isEmpty()) {
                            throw new SOPGPException.NoSignature();
                        }
                    }

                    return verificationList;
                } catch (MissingDecryptionMethodException e) {
                    throw new SOPGPException.BadData("Cannot verify encrypted message.", e);
                } catch (MalformedOpenPgpMessageException | PGPException e) {
                    throw new SOPGPException.BadData(e);
                }
            }
        };
    }
}
