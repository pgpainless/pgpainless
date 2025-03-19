// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.RevocationAttributes;

public class UserIdRevocationTest {

    @Test
    public void testRevocationWithoutRevocationAttributes() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                        KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(
                        KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS))
                .addUserId("primary@key.id")
                .addUserId("secondary@key.id")
                .build();

        // make a copy with revoked subkey
        OpenPGPKey revoked = api.modify(secretKeys)
                .revokeUserId("secondary@key.id", new UnprotectedKeysProtector())
                .done();

        KeyRingInfo info = api.inspect(revoked);
        List<String> userIds = info.getUserIds();
        assertEquals(Arrays.asList("primary@key.id", "secondary@key.id"), userIds);
        assertTrue(info.isUserIdValid("primary@key.id"));
        assertFalse(info.isUserIdValid("sedondary@key.id"));
        assertFalse(info.isUserIdValid("tertiary@key.id"));

        info = api.inspect(secretKeys);
        assertTrue(info.isUserIdValid("secondary@key.id")); // key on original secret key ring is still valid

        revoked = api.modify(secretKeys)
                .revokeUserId("secondary@key.id", new UnprotectedKeysProtector())
                .done();
        info = api.inspect(revoked);
        userIds = info.getUserIds();
        assertEquals(Arrays.asList("primary@key.id", "secondary@key.id"), userIds);
        assertTrue(info.isUserIdValid("primary@key.id"));
        assertFalse(info.isUserIdValid("sedondary@key.id"));
        assertFalse(info.isUserIdValid("tertiary@key.id"));
    }

    @Test
    public void testRevocationWithRevocationReason() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                        KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS))
                .addUserId("primary@key.id")
                .addUserId("secondary@key.id")
                .build();

        secretKeys = api.modify(secretKeys)
                .revokeUserId("secondary@key.id", new UnprotectedKeysProtector(),
                        RevocationAttributes.createCertificateRevocation()
                                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                                .withDescription("I lost my mail password"))
                .done();
        KeyRingInfo info = api.inspect(secretKeys);

        PGPSignature signature = info.getUserIdRevocation("secondary@key.id");
        assertNotNull(signature);
        RevocationReason reason = (RevocationReason) signature.getHashedSubPackets()
                .getSubpacket(SignatureSubpacketTags.REVOCATION_REASON);
        assertNotNull(reason);
        assertEquals("I lost my mail password", reason.getRevocationDescription());
    }

    @Test
    public void unknownKeyThrowsIllegalArgumentException() throws IOException, PGPException {
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(NoSuchElementException.class, () -> PGPainless.getInstance().modify(secretKeys)
                .revokeSubKey(new KeyIdentifier(1L), protector));
    }

    @Test
    public void unknownUserIdThrowsNoSuchElementException() throws IOException, PGPException {
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(NoSuchElementException.class, () -> PGPainless.getInstance().modify(secretKeys)
                .revokeUserId("invalid@user.id", protector));
    }

    @Test
    public void invalidRevocationReasonThrowsIllegalArgumentException() throws IOException, PGPException {
        OpenPGPKey secretKeys = TestKeys.getCryptieKey();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys, TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(IllegalArgumentException.class, () -> PGPainless.getInstance().modify(secretKeys)
                .revokeUserId("cryptie@encrypted.key", protector,
                        RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED)
                                .withDescription("This is not a valid certification revocation reason.")));
    }
}
