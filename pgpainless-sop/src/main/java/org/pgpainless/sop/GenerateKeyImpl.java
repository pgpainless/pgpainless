// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.Passphrase;
import sop.Profile;
import sop.Ready;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

import javax.annotation.Nonnull;

/**
 * Implementation of the <pre>generate-key</pre> operation using PGPainless.
 */
public class GenerateKeyImpl implements GenerateKey {

    public static final Profile CURVE25519_PROFILE = new Profile("draft-koch-eddsa-for-openpgp-00", "Generate EdDSA / ECDH keys using Curve25519");
    public static final Profile RSA4096_PROFILE = new Profile("rfc4880", "Generate 4096-bit RSA keys");

    public static final List<Profile> SUPPORTED_PROFILES = Arrays.asList(CURVE25519_PROFILE, RSA4096_PROFILE);

    private boolean armor = true;
    private boolean signingOnly = false;
    private final Set<String> userIds = new LinkedHashSet<>();
    private Passphrase passphrase = Passphrase.emptyPassphrase();
    private String profile = CURVE25519_PROFILE.getName();

    @Override
    @Nonnull
    public GenerateKey noArmor() {
        this.armor = false;
        return this;
    }

    @Override
    @Nonnull
    public GenerateKey userId(@Nonnull String userId) {
        this.userIds.add(userId);
        return this;
    }

    @Override
    @Nonnull
    public GenerateKey withKeyPassword(@Nonnull String password) {
        this.passphrase = Passphrase.fromPassword(password);
        return this;
    }

    @Override
    @Nonnull
    public GenerateKey profile(@Nonnull String profileName) {
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
    @Nonnull
    public GenerateKey signingOnly() {
        signingOnly = true;
        return this;
    }

    @Override
    @Nonnull
    public Ready generate() throws SOPGPException.MissingArg, SOPGPException.UnsupportedAsymmetricAlgo {
        try {
            final PGPSecretKeyRing key = generateKeyWithProfile(profile, userIds, passphrase, signingOnly);
            return new Ready() {
                @Override
                public void writeTo(@Nonnull OutputStream outputStream) throws IOException {
                    if (armor) {
                        ArmoredOutputStream armoredOutputStream = ArmorUtils.toAsciiArmoredStream(key, outputStream);
                        key.encode(armoredOutputStream);
                        armoredOutputStream.close();
                    } else {
                        key.encode(outputStream);
                    }
                }
            };
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", e);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        }
    }

    private PGPSecretKeyRing generateKeyWithProfile(String profile, Set<String> userIds, Passphrase passphrase, boolean signingOnly)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        KeyRingBuilder keyBuilder;
        // XDH + EdDSA
        if (profile.equals(CURVE25519_PROFILE.getName())) {
            keyBuilder = PGPainless.buildKeyRing()
                    .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                    .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA));
            if (!signingOnly) {
                keyBuilder.addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE));
            }
        }
        // RSA 4096
        else if (profile.equals(RSA4096_PROFILE.getName())) {
            keyBuilder = PGPainless.buildKeyRing()
                    .setPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.CERTIFY_OTHER))
                    .addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.SIGN_DATA));
            if (!signingOnly) {
                keyBuilder.addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE));
            }
        }
        else {
            // Missing else-if branch for profile. Oops.
            throw new SOPGPException.UnsupportedProfile("generate-key", profile);
        }

        for (String userId : userIds) {
            keyBuilder.addUserId(userId);
        }
        if (!passphrase.isEmpty()) {
            keyBuilder.setPassphrase(passphrase);
        }
        return keyBuilder.build();
    }
}
