// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.ascii_armor.ArmorUtils;
import org.pgpainless.s2k.Passphrase;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

public class GenerateKeyImpl implements GenerateKey {

    private boolean armor = true;
    private final Set<String> userIds = new LinkedHashSet<>();
    private Passphrase passphrase;

    @Override
    public GenerateKey noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    public GenerateKey userId(String userId) {
        this.userIds.add(userId);
        return this;
    }

    @Override
    public GenerateKey withKeyPassword(String password) {
        this.passphrase = Passphrase.fromPassword(password);
        return this;
    }

    @Override
    public Ready generate() throws SOPGPException.MissingArg, SOPGPException.UnsupportedAsymmetricAlgo {
        Iterator<String> userIdIterator = userIds.iterator();
        if (!userIdIterator.hasNext()) {
            throw new SOPGPException.MissingArg("Missing user-id.");
        }

        PGPSecretKeyRing key;
        try {
             key = PGPainless.generateKeyRing()
                    .modernKeyRing(userIdIterator.next(), passphrase);

            if (userIdIterator.hasNext()) {
                SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(key);

                while (userIdIterator.hasNext()) {
                    editor.addUserId(userIdIterator.next(), SecretKeyRingProtector.unprotectedKeys());
                }

                key = editor.done();
            }

            PGPSecretKeyRing finalKey = key;
            return new Ready() {
                @Override
                public void writeTo(OutputStream outputStream) throws IOException {
                    if (armor) {
                        ArmoredOutputStream armoredOutputStream = ArmorUtils.toAsciiArmoredStream(finalKey, outputStream);
                        finalKey.encode(armoredOutputStream);
                        armoredOutputStream.close();
                    } else {
                        finalKey.encode(outputStream);
                    }
                }
            };
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", e);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }
}
