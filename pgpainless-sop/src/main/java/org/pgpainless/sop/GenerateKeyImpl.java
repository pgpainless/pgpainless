// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.Passphrase;
import sop.Profile;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

/**
 * Implementation of the <pre>generate-key</pre> operation using PGPainless.
 */
public class GenerateKeyImpl implements GenerateKey {

    public static final Profile CURVE25519_PROFILE = new Profile("draft-koch-eddsa-for-openpgp-00", "Generate EdDSA / ECDH keys using Curve25519");
    public static final Profile RSA4096_PROFILE = new Profile("rfc4880", "Generate 4096-bit RSA keys");

    public static final List<Profile> SUPPORTED_PROFILES = Arrays.asList(CURVE25519_PROFILE, RSA4096_PROFILE);

    private boolean armor = true;
    private final Set<String> userIds = new LinkedHashSet<>();
    private Passphrase passphrase = Passphrase.emptyPassphrase();
    private String profile = CURVE25519_PROFILE.getName();

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
    public GenerateKey profile(String profileName) {
        // Sanitize the profile name to make sure we support the given profile
        for (Profile profile : SUPPORTED_PROFILES) {
            if (profile.getName().equals(profileName)) {
                this.profile = profileName;
                // return if we found the profile
                return this;
            }
        }

        // profile not found, throw
        throw new SOPGPException.UnsupportedProfile("generate-key", profileName);
    }

    @Override
    public Ready generate() throws SOPGPException.MissingArg, SOPGPException.UnsupportedAsymmetricAlgo {
        Iterator<String> userIdIterator = userIds.iterator();
        Passphrase passphraseCopy = new Passphrase(passphrase.getChars()); // generateKeyRing clears the original passphrase
        PGPSecretKeyRing key;
        try {
            String primaryUserId = userIdIterator.hasNext() ? userIdIterator.next() : null;
            key = generateKeyWithProfile(profile, primaryUserId, passphrase);

            if (userIdIterator.hasNext()) {
                SecretKeyRingEditorInterface editor = PGPainless.modifyKeyRing(key);

                while (userIdIterator.hasNext()) {
                    editor.addUserId(userIdIterator.next(), SecretKeyRingProtector.unlockAnyKeyWith(passphraseCopy));
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

    private PGPSecretKeyRing generateKeyWithProfile(String profile, String primaryUserId, Passphrase passphrase)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing key;
        // XDH + EdDSA
        if (profile.equals(CURVE25519_PROFILE.getName())) {
            key = PGPainless.generateKeyRing()
                    .modernKeyRing(primaryUserId, passphrase);
        }
        // RSA 4096
        else if (profile.equals(RSA4096_PROFILE.getName())) {
            key = PGPainless.generateKeyRing()
                    .simpleRsaKeyRing(primaryUserId, RsaLength._4096, passphrase);
        }
        else {
            // Missing else-if branch for profile. Oops.
            throw new SOPGPException.UnsupportedProfile("generate-key", profile);
        }
        return key;
    }
}
