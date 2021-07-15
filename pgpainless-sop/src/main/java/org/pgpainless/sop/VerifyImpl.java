/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.SubkeyIdentifier;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Verify;

public class VerifyImpl implements Verify {

    ConsumerOptions options = new ConsumerOptions();

    @Override
    public Verify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            options.verifyNotBefore(timestamp);
        } catch (NotYetImplementedException e) {
            // throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public Verify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            options.verifyNotAfter(timestamp);
        } catch (NotYetImplementedException e) {
            // throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public Verify cert(InputStream cert) throws SOPGPException.BadData {
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
    public VerifyImpl signatures(InputStream signatures) throws SOPGPException.BadData {
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

            for (SubkeyIdentifier verifiedSigningKey : metadata.getVerifiedSignatures().keySet()) {
                PGPSignature signature = metadata.getVerifiedSignatures().get(verifiedSigningKey);
                Date verifyNotBefore = options.getVerifyNotBefore();
                Date verifyNotAfter = options.getVerifyNotAfter();

                if (verifyNotAfter == null || !signature.getCreationTime().after(verifyNotAfter)) {
                    if (verifyNotBefore == null || !signature.getCreationTime().before(verifyNotBefore)) {
                        verificationList.add(new Verification(
                                signature.getCreationTime(),
                                verifiedSigningKey.getSubkeyFingerprint().toString(),
                                verifiedSigningKey.getPrimaryKeyFingerprint().toString()));
                    }
                }
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
}
