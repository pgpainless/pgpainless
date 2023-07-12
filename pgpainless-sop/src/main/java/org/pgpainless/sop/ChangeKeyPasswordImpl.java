// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.exception.MissingPassphraseException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.Passphrase;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.ChangeKeyPassword;

public class ChangeKeyPasswordImpl implements ChangeKeyPassword {

    private final MatchMakingSecretKeyRingProtector oldProtector = new MatchMakingSecretKeyRingProtector();
    private Passphrase newPassphrase = Passphrase.emptyPassphrase();
    private boolean armor = true;

    @Override
    public ChangeKeyPassword noArmor() {
        armor = false;
        return this;
    }

    @Override
    public ChangeKeyPassword oldKeyPassphrase(String oldPassphrase) {
        oldProtector.addPassphrase(Passphrase.fromPassword(oldPassphrase));
        return this;
    }

    @Override
    public ChangeKeyPassword newKeyPassphrase(String newPassphrase) {
        this.newPassphrase = Passphrase.fromPassword(newPassphrase);
        return this;
    }

    @Override
    public Ready keys(InputStream inputStream) throws SOPGPException.KeyIsProtected {
        SecretKeyRingProtector newProtector = SecretKeyRingProtector.unlockAnyKeyWith(newPassphrase);
        PGPSecretKeyRingCollection secretKeyRingCollection;
        try {
            secretKeyRingCollection = KeyReader.readSecretKeys(inputStream, true);
        } catch (IOException e) {
            throw new SOPGPException.BadData(e);
        }

        List<PGPSecretKeyRing> updatedSecretKeys = new ArrayList<>();
        for (PGPSecretKeyRing secretKeys : secretKeyRingCollection) {
            oldProtector.addSecretKey(secretKeys);
            try {
                PGPSecretKeyRing changed = KeyRingUtils.changePassphrase(null, secretKeys, oldProtector, newProtector);
                updatedSecretKeys.add(changed);
            } catch (MissingPassphraseException e) {
                throw new SOPGPException.KeyIsProtected("Cannot unlock key " + OpenPgpFingerprint.of(secretKeys), e);
            } catch (PGPException e) {
                if (e.getMessage().contains("Exception decrypting key")) {
                    throw new SOPGPException.KeyIsProtected("Cannot unlock key " + OpenPgpFingerprint.of(secretKeys), e);
                }
                throw new RuntimeException("Cannot change passphrase of key " + OpenPgpFingerprint.of(secretKeys), e);
            }
        }
        final PGPSecretKeyRingCollection changedSecretKeyCollection = new PGPSecretKeyRingCollection(updatedSecretKeys);
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                if (armor) {
                    ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(outputStream);
                    changedSecretKeyCollection.encode(armorOut);
                    armorOut.close();
                } else {
                    changedSecretKeyCollection.encode(outputStream);
                }
            }
        };
    }
}
