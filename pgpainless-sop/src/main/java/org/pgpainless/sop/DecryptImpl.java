// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
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
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
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
        consumerOptions.verifyNotBefore(timestamp);
        return this;
    }

    @Override
    public DecryptImpl verifyNotAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        consumerOptions.verifyNotAfter(timestamp);
        return this;
    }

    @Override
    public DecryptImpl verifyWithCert(InputStream certIn) throws SOPGPException.BadData, IOException {
        try {
            PGPPublicKeyRingCollection certs = PGPainless.readKeyRing().keyRingCollection(certIn, false)
                    .getPgpPublicKeyRingCollection();
            if (certs.size() == 0) {
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
        consumerOptions.setSessionKey(
                new org.pgpainless.util.SessionKey(
                        SymmetricKeyAlgorithm.fromId(sessionKey.getAlgorithm()),
                        sessionKey.getKey()));
        return this;
    }

    @Override
    public DecryptImpl withPassword(String password) {
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
                    .secretKeyRingCollection(keyIn);

            if (secretKeys.size() != 1) {
                throw new SOPGPException.BadData(new AssertionError("Exactly one single secret key expected. Got " + secretKeys.size()));
            }

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

        if (consumerOptions.getDecryptionKeys().isEmpty() && consumerOptions.getDecryptionPassphrases().isEmpty() && consumerOptions.getSessionKey() == null) {
            throw new SOPGPException.MissingArg("Missing decryption key, passphrase or session key.");
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
                    verificationList.add(new Verification(
                            signature.getCreationTime(),
                            verifiedSigningKey.getSubkeyFingerprint().toString(),
                            verifiedSigningKey.getPrimaryKeyFingerprint().toString()));
                }

                if (!consumerOptions.getCertificates().isEmpty()) {
                    if (verificationList.isEmpty()) {
                        throw new SOPGPException.NoSignature();
                    }
                }

                SessionKey sessionKey = null;
                if (metadata.getSessionKey() != null) {
                    org.pgpainless.util.SessionKey sk = metadata.getSessionKey();
                    sessionKey = new SessionKey(
                            (byte) sk.getAlgorithm().getAlgorithmId(),
                            sk.getKey()
                    );
                }

                return new DecryptionResult(sessionKey, verificationList);
            }
        };
    }
}
