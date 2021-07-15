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
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

public class DecryptImpl implements Decrypt {

    private final ConsumerOptions consumerOptions = new ConsumerOptions();

    @Override
    public DecryptImpl verifyNotBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            consumerOptions.verifyNotBefore(timestamp);
        } catch (NotYetImplementedException e) {
            // throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public DecryptImpl verifyNotAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        try {
            consumerOptions.verifyNotAfter(timestamp);
        } catch (NotYetImplementedException e) {
            // throw new SOPGPException.UnsupportedOption();
        }
        return this;
    }

    @Override
    public DecryptImpl verifyWithCert(InputStream certIn) throws SOPGPException.BadData, IOException {
        try {
            PGPPublicKeyRingCollection certs = PGPainless.readKeyRing().keyRingCollection(certIn, false)
                    .getPgpPublicKeyRingCollection();
            if (certs == null) {
                throw new SOPGPException.BadData(new PGPException("No certificates provided."));
            }

            consumerOptions.addVerificationCerts(certs);

        } catch (PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public DecryptImpl withSessionKey(SessionKey sessionKey) throws SOPGPException.UnsupportedOption {
        throw new SOPGPException.UnsupportedOption();
    }

    @Override
    public DecryptImpl withPassword(String password) throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        consumerOptions.addDecryptionPassphrase(Passphrase.fromPassword(password));
        String withoutTrailingWhitespace = removeTrailingWhitespace(password);
        if (!password.equals(withoutTrailingWhitespace)) {
            consumerOptions.addDecryptionPassphrase(Passphrase.fromPassword(withoutTrailingWhitespace));
        }
        return this;
    }

    private static String removeTrailingWhitespace(String passphrase) {
        int i = passphrase.length() - 1;
        // Find index of first non-whitespace character from the back
        while (i > 0 && Character.isWhitespace(passphrase.charAt(i))) {
            i--;
        }
        return passphrase.substring(0, i);
    }

    @Override
    public DecryptImpl withKey(InputStream keyIn) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo {
        try {
            PGPSecretKeyRingCollection secretKeys = PGPainless.readKeyRing()
                    .keyRingCollection(keyIn, true)
                    .getPGPSecretKeyRingCollection();

            for (PGPSecretKeyRing secretKey : secretKeys) {
                KeyRingInfo info = new KeyRingInfo(secretKey);
                if (!info.isFullyDecrypted()) {
                    throw new SOPGPException.KeyIsProtected();
                }
            }

            consumerOptions.addDecryptionKeys(secretKeys, SecretKeyRingProtector.unprotectedKeys());
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public ReadyWithResult<DecryptionResult> ciphertext(InputStream ciphertext)
            throws SOPGPException.BadData,
            SOPGPException.MissingArg {

        if (consumerOptions.getDecryptionKeys().isEmpty() && consumerOptions.getDecryptionPassphrases().isEmpty()) {
            throw new SOPGPException.MissingArg("Missing decryption key or passphrase.");
        }

        DecryptionStream decryptionStream;
        try {
            decryptionStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(ciphertext)
                    .withOptions(consumerOptions);
        } catch (PGPException | IOException e) {
            throw new SOPGPException.BadData(e);
        }

        return new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                Streams.pipeAll(decryptionStream, outputStream);
                decryptionStream.close();
                OpenPgpMetadata metadata = decryptionStream.getResult();

                List<Verification> verificationList = new ArrayList<>();
                for (SubkeyIdentifier verifiedSigningKey : metadata.getVerifiedSignatures().keySet()) {
                    PGPSignature signature = metadata.getVerifiedSignatures().get(verifiedSigningKey);
                    Date verifyNotBefore = consumerOptions.getVerifyNotBefore();
                    Date verifyNotAfter = consumerOptions.getVerifyNotAfter();

                    if (verifyNotAfter == null || !signature.getCreationTime().after(verifyNotAfter)) {
                        if (verifyNotBefore == null || !signature.getCreationTime().before(verifyNotBefore)) {
                            verificationList.add(new Verification(
                                    signature.getCreationTime(),
                                    verifiedSigningKey.getSubkeyFingerprint().toString(),
                                    verifiedSigningKey.getPrimaryKeyFingerprint().toString()));
                        }
                    }
                }

                if (!consumerOptions.getCertificates().isEmpty()) {
                    if (verificationList.isEmpty()) {
                        throw new SOPGPException.NoSignature();
                    }
                }

                return new DecryptionResult(null, verificationList);
            }
        };
    }
}
