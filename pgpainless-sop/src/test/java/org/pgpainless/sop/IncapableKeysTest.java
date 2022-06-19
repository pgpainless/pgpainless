// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.util.ArmorUtils;
import sop.SOP;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class IncapableKeysTest {

    private static byte[] nonSigningKey;
    private static byte[] nonEncryptionKey;
    private static byte[] nonSigningCert;
    private static byte[] nonEncryptionCert;

    private static final SOP sop = new SOPImpl();

    @BeforeAll
    public static void generateKeys() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing key = PGPainless.buildKeyRing()
                .addSubkey(KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._P256), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addUserId("Non Signing <non@signing.key>")
                .build();
        nonSigningKey = ArmorUtils.toAsciiArmoredString(key).getBytes(StandardCharsets.UTF_8);
        nonSigningCert = sop.extractCert().key(nonSigningKey).getBytes();

        key = PGPainless.buildKeyRing()
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addUserId("Non Encryption <non@encryption.key>")
                .build();
        nonEncryptionKey = ArmorUtils.toAsciiArmoredString(key).getBytes(StandardCharsets.UTF_8);
        nonEncryptionCert = sop.extractCert().key(nonEncryptionKey).getBytes();
    }

    @Test
    public void encryptionToNonEncryptionKeyFails() {
        assertThrows(SOPGPException.CertCannotEncrypt.class, () -> sop.encrypt().withCert(nonEncryptionCert));
    }

    @Test
    public void signingWithNonSigningKeyFails() {
        assertThrows(SOPGPException.KeyCannotSign.class, () -> sop.sign().key(nonSigningKey));
        assertThrows(SOPGPException.KeyCannotSign.class, () -> sop.detachedSign().key(nonSigningKey));
        assertThrows(SOPGPException.KeyCannotSign.class, () -> sop.inlineSign().key(nonSigningKey));
    }

    @Test
    public void encryptAndSignWithNonSigningKeyFails() {
        assertThrows(SOPGPException.KeyCannotSign.class, () -> sop.encrypt().signWith(nonSigningKey));
    }
}
