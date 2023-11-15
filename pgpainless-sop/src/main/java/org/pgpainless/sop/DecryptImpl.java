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
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.exception.MalformedOpenPgpMessageException;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.util.Passphrase;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SessionKey;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;
import sop.util.UTF8Util;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>decrypt</pre> operation using PGPainless.
 */
public class DecryptImpl implements Decrypt {

    private final ConsumerOptions consumerOptions = ConsumerOptions.get();
    private final MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();

    @Nonnull
    @Override
    public DecryptImpl verifyNotBefore(@Nonnull Date timestamp) throws SOPGPException.UnsupportedOption {
        consumerOptions.verifyNotBefore(timestamp);
        return this;
    }

    @Nonnull
    @Override
    public DecryptImpl verifyNotAfter(@Nonnull Date timestamp) throws SOPGPException.UnsupportedOption {
        consumerOptions.verifyNotAfter(timestamp);
        return this;
    }

    @Nonnull
    @Override
    public DecryptImpl verifyWithCert(@Nonnull InputStream certIn) throws SOPGPException.BadData, IOException {
        PGPPublicKeyRingCollection certs = KeyReader.readPublicKeys(certIn, true);
        if (certs != null) {
            consumerOptions.addVerificationCerts(certs);
        }
        return this;
    }

    @Nonnull
    @Override
    public DecryptImpl withSessionKey(@Nonnull SessionKey sessionKey) throws SOPGPException.UnsupportedOption {
        consumerOptions.setSessionKey(
                new org.pgpainless.util.SessionKey(
                        SymmetricKeyAlgorithm.requireFromId(sessionKey.getAlgorithm()),
                        sessionKey.getKey()));
        return this;
    }

    @Nonnull
    @Override
    public DecryptImpl withPassword(@Nonnull String password) {
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

    @Nonnull
    @Override
    public DecryptImpl withKey(@Nonnull InputStream keyIn) throws SOPGPException.BadData, IOException, SOPGPException.UnsupportedAsymmetricAlgo {
        PGPSecretKeyRingCollection secretKeyCollection = KeyReader.readSecretKeys(keyIn, true);

        for (PGPSecretKeyRing key : secretKeyCollection) {
            protector.addSecretKey(key);
            consumerOptions.addDecryptionKey(key, protector);
        }
        return this;
    }

    @Nonnull
    @Override
    public Decrypt withKeyPassword(@Nonnull byte[] password) {
        String string = new String(password, UTF8Util.UTF8);
        protector.addPassphrase(Passphrase.fromPassword(string));
        return this;
    }

    @Nonnull
    @Override
    public ReadyWithResult<DecryptionResult> ciphertext(@Nonnull InputStream ciphertext)
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
            throw new SOPGPException.CannotDecrypt("No usable decryption key or password provided.", e);
        } catch (WrongPassphraseException e) {
            throw new SOPGPException.KeyIsProtected();
        } catch (MalformedOpenPgpMessageException | PGPException | IOException e) {
            throw new SOPGPException.BadData(e);
        } finally {
            // Forget passphrases after decryption
            protector.clear();
        }

        return new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(@Nonnull OutputStream outputStream) throws IOException, SOPGPException.NoSignature {
                Streams.pipeAll(decryptionStream, outputStream);
                decryptionStream.close();
                MessageMetadata metadata = decryptionStream.getMetadata();

                if (!metadata.isEncrypted()) {
                    throw new SOPGPException.BadData("Data is not encrypted.");
                }

                List<Verification> verificationList = new ArrayList<>();
                for (SignatureVerification signatureVerification : metadata.getVerifiedInlineSignatures()) {
                    verificationList.add(VerificationHelper.mapVerification(signatureVerification));
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
