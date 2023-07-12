// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.CharacterCodingException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.WrongPassphraseException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.Passphrase;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.RevokeKey;
import sop.util.UTF8Util;

public class RevokeKeyImpl implements RevokeKey {

    private final MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
    private boolean armor = true;

    public RevokeKey noArmor() {
        this.armor = false;
        return this;
    }

    /**
     * Provide the decryption password for the secret key.
     *
     * @param password password
     * @return builder instance
     * @throws sop.exception.SOPGPException.UnsupportedOption if the implementation does not support key passwords
     * @throws sop.exception.SOPGPException.PasswordNotHumanReadable if the password is not human-readable
     */
    public RevokeKey withKeyPassword(byte[] password)
            throws SOPGPException.UnsupportedOption,
            SOPGPException.PasswordNotHumanReadable {
        String string;
        try {
            string = UTF8Util.decodeUTF8(password);
        } catch (CharacterCodingException e) {
            throw new SOPGPException.PasswordNotHumanReadable("Cannot UTF8-decode password.");
        }
        protector.addPassphrase(Passphrase.fromPassword(string));
        return this;
    }

    public Ready keys(InputStream keys) throws SOPGPException.BadData {
        PGPSecretKeyRingCollection secretKeyRings;
        try {
            secretKeyRings = KeyReader.readSecretKeys(keys, true);
        } catch (IOException e) {
            throw new SOPGPException.BadData("Cannot decode secret keys.", e);
        }
        for (PGPSecretKeyRing secretKeys : secretKeyRings) {
            protector.addSecretKey(secretKeys);
        }

        final List<PGPPublicKeyRing> revocationCertificates = new ArrayList<>();
        for (PGPSecretKeyRing secretKeys : secretKeyRings) {
            SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(secretKeys);
            try {
                RevocationAttributes revocationAttributes = RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.NO_REASON)
                        .withoutDescription();
                if (secretKeys.getPublicKey().getVersion() == PublicKeyPacket.VERSION_6) {
                    PGPPublicKeyRing revocation = editor.createMinimalRevocationCertificate(protector, revocationAttributes);
                    revocationCertificates.add(revocation);
                } else {
                    PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKeys);
                    PGPSignature revocation = editor.createRevocation(protector, revocationAttributes);
                    certificate = KeyRingUtils.injectCertification(certificate, revocation);
                    revocationCertificates.add(certificate);
                }
            } catch (WrongPassphraseException e) {
                throw new SOPGPException.KeyIsProtected("Missing or wrong passphrase for key " + OpenPgpFingerprint.of(secretKeys), e);
            }
            catch (PGPException e) {
                throw new RuntimeException("Cannot generate revocation certificate.", e);
            }
        }

        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                PGPPublicKeyRingCollection certificateCollection = new PGPPublicKeyRingCollection(revocationCertificates);
                if (armor) {
                    ArmoredOutputStream out = ArmoredOutputStreamFactory.get(outputStream);
                    certificateCollection.encode(out);
                    out.close();
                } else {
                    certificateCollection.encode(outputStream);
                }
            }
        };
    }
}
