// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.s2k.Passphrase;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;

public class DecryptImpl implements Decrypt {

    private final ConsumerOptions consumerOptions = ConsumerOptions.get();
    private final MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();

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
                new org.pgpainless.s2k.SessionKey(
                        SymmetricKeyAlgorithm.requireFromId(sessionKey.getAlgorithm()),
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
    public DecryptImpl withKey(InputStream keyIn) throws SOPGPException.BadData, SOPGPException.UnsupportedAsymmetricAlgo {
        try {
            PGPSecretKeyRingCollection secretKeyCollection = PGPainless.readKeyRing()
                    .secretKeyRingCollection(keyIn);
            for (PGPSecretKeyRing key : secretKeyCollection) {
                protector.addSecretKey(key);
                consumerOptions.addDecryptionKey(key, protector);
            }
        } catch (IOException | PGPException e) {
            throw new SOPGPException.BadData(e);
        }
        return this;
    }

    @Override
    public Decrypt withKeyPassword(byte[] password) {
        String string = new String(password, Charset.forName("UTF8"));
        protector.addPassphrase(Passphrase.fromPassword(string));
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
        } catch (MissingDecryptionMethodException e) {
            throw new SOPGPException.CannotDecrypt();
        } catch (WrongPassphraseException e) {
            throw new SOPGPException.KeyIsProtected();
        } catch (PGPException | IOException e) {
            throw new SOPGPException.BadData(e);
        } finally {
            // Forget passphrases after decryption
            protector.clear();
        }

        return new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                Streams.pipeAll(decryptionStream, outputStream);
                decryptionStream.close();
                OpenPgpMetadata metadata = decryptionStream.getResult();

                if (!metadata.isEncrypted()) {
                    throw new SOPGPException.BadData("Data is not encrypted.");
                }

                List<Verification> verificationList = new ArrayList<>();
                for (SignatureVerification signatureVerification : metadata.getVerifiedInbandSignatures()) {
                    verificationList.add(map(signatureVerification));
                }

                SessionKey sessionKey = null;
                if (metadata.getSessionKey() != null) {
                    org.pgpainless.s2k.SessionKey sk = metadata.getSessionKey();
                    sessionKey = new SessionKey(
                            (byte) sk.getAlgorithm().getAlgorithmId(),
                            sk.getKey()
                    );
                }

                return new DecryptionResult(sessionKey, verificationList);
            }
        };
    }

    private Verification map(SignatureVerification sigVerification) {
        return new Verification(sigVerification.getSignature().getCreationTime(),
                sigVerification.getSigningKey().getSubkeyFingerprint().toString(),
                sigVerification.getSigningKey().getPrimaryKeyFingerprint().toString());
    }
}
