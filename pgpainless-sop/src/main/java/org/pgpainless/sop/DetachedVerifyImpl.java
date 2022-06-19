// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
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
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.DetachedVerify;

public class DetachedVerifyImpl implements DetachedVerify {

    private final ConsumerOptions options = new ConsumerOptions();

    @Override
    public DetachedVerify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotBefore(timestamp);
        return this;
    }

    @Override
    public DetachedVerify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        options.verifyNotAfter(timestamp);
        return this;
    }

    @Override
    public DetachedVerify cert(InputStream cert) throws SOPGPException.BadData {
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
    public DetachedVerifyImpl signatures(InputStream signatures) throws SOPGPException.BadData {
        try {
            options.addVerificationOfDetachedSignatures(signatures);
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public List<Verification> data(InputStream data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData {
        DecryptionStream decryptionStream;
        try {
            decryptionStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(data)
                    .withOptions(options);

            Streams.drain(decryptionStream);
            decryptionStream.close();

            OpenPgpMetadata metadata = decryptionStream.getResult();
            List<Verification> verificationList = new ArrayList<>();

            for (SignatureVerification signatureVerification : metadata.getVerifiedDetachedSignatures()) {
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

    private Verification map(SignatureVerification sigVerification) {
        return new Verification(sigVerification.getSignature().getCreationTime(),
                sigVerification.getSigningKey().getSubkeyFingerprint().toString(),
                sigVerification.getSigningKey().getPrimaryKeyFingerprint().toString());
    }
}
