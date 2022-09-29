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
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.decryption_verification.SignatureVerification;
import sop.ReadyWithResult;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.InlineVerify;

public class InlineVerifyImpl implements InlineVerify {

    private final ConsumerOptions options = ConsumerOptions.get();

    @Override
    public InlineVerify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotBefore(timestamp);
        return this;
    }

    @Override
    public InlineVerify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotAfter(timestamp);
        return this;
    }

    @Override
    public InlineVerify cert(InputStream cert) throws SOPGPException.BadData {
        PGPPublicKeyRingCollection certificates;
        try {
            certificates = PGPainless.readKeyRing().publicKeyRingCollection(cert);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        options.addVerificationCerts(certificates);
        return this;
    }

    @Override
    public ReadyWithResult<List<Verification>> data(InputStream data) throws SOPGPException.NoSignature, SOPGPException.BadData {
        return new ReadyWithResult<List<Verification>>() {
            @Override
            public List<Verification> writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                DecryptionStream decryptionStream;
                try {
                    decryptionStream = PGPainless.decryptAndOrVerify()
                            .onInputStream(data)
                            .withOptions(options);

                    Streams.pipeAll(decryptionStream, outputStream);
                    decryptionStream.close();

                    OpenPgpMetadata metadata = decryptionStream.getResult();
                    List<Verification> verificationList = new ArrayList<>();

                    List<SignatureVerification> verifications = metadata.isCleartextSigned() ?
                            metadata.getVerifiedDetachedSignatures() :
                            metadata.getVerifiedInbandSignatures();

                    for (SignatureVerification signatureVerification : verifications) {
                        verificationList.add(map(signatureVerification));
                    }

                    if (!options.getCertificates().isEmpty()) {
                        if (verificationList.isEmpty()) {
                            throw new SOPGPException.NoSignature();
                        }
                    }

                    return verificationList;
                } catch (PGPException e) {
                    throw new SOPGPException.BadData(e);
                }
            }
        };
    }

    private Verification map(SignatureVerification sigVerification) {
        return new Verification(sigVerification.getSignature().getCreationTime(),
                sigVerification.getSigningKey().getSubkeyFingerprint().toString(),
                sigVerification.getSigningKey().getPrimaryKeyFingerprint().toString());
    }
}
