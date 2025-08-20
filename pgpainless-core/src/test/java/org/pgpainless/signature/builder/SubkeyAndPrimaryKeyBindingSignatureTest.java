// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;

public class SubkeyAndPrimaryKeyBindingSignatureTest {

    @Test
    public void testRebindSubkey() throws PGPException, IOException {
        OpenPGPKey secretKeys = PGPainless.getInstance().toKey(TestKeys.getEmilSecretKeyRing());
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        OpenPGPKey.OpenPGPSecretKey primaryKey = secretKeys.getPrimarySecretKey();
        OpenPGPCertificate.OpenPGPComponentKey encryptionSubkey =
                info.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0);
        assertNotNull(encryptionSubkey);

        Set<HashAlgorithm> hashAlgorithmSet = info.getPreferredHashAlgorithms(encryptionSubkey.getKeyIdentifier());
        assertEquals(
                new HashSet<>(Arrays.asList(
                        HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256, HashAlgorithm.SHA224)),
                hashAlgorithmSet);

        SubkeyBindingSignatureBuilder sbb = new SubkeyBindingSignatureBuilder(primaryKey, SecretKeyRingProtector.unprotectedKeys());
        sbb.applyCallback(new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                hashedSubpackets.setKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE);
                hashedSubpackets.setPreferredHashAlgorithms(HashAlgorithm.SHA512);
            }
        });

        PGPSignature binding = sbb.build(encryptionSubkey.getPGPPublicKey());
        PGPSecretKeyRing secretKeyRing = KeyRingUtils.injectCertification(secretKeys.getPGPKeyRing(), encryptionSubkey.getPGPPublicKey(), binding);

        info = PGPainless.inspectKeyRing(secretKeyRing);
        assertEquals(Collections.singleton(HashAlgorithm.SHA512), info.getPreferredHashAlgorithms(encryptionSubkey.getKeyIdentifier()));
    }
}
