// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Collections;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class ThirdPartyDirectKeySignatureBuilderTest {

    @Test
    public void testDirectKeySignatureBuilding() throws PGPException {
        OpenPGPKey secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice");

        DirectKeySelfSignatureBuilder dsb = new DirectKeySelfSignatureBuilder(
                secretKeys.getPrimarySecretKey(),
                SecretKeyRingProtector.unprotectedKeys());

        Date now = new Date();
        Date t1 = new Date(now.getTime() + 1000 * 60 * 60);
        dsb.applyCallback(new SelfSignatureSubpackets.Callback() {
            @Override
            public void modifyHashedSubpackets(SelfSignatureSubpackets hashedSubpackets) {
                hashedSubpackets.setSignatureCreationTime(t1);
                hashedSubpackets.setKeyFlags(KeyFlag.CERTIFY_OTHER);
                hashedSubpackets.setPreferredHashAlgorithms(HashAlgorithm.SHA512);
                hashedSubpackets.setPreferredCompressionAlgorithms(CompressionAlgorithm.ZIP);
                hashedSubpackets.setPreferredSymmetricKeyAlgorithms(SymmetricKeyAlgorithm.AES_256);
                hashedSubpackets.setFeatures(Feature.MODIFICATION_DETECTION);
            }
        });

        OpenPGPSignature directKeySig = dsb.build();
        assertNotNull(directKeySig);
        PGPSecretKeyRing secretKeyRing = KeyRingUtils.injectCertification(
                secretKeys.getPGPSecretKeyRing(),
                secretKeys.getPrimaryKey().getPGPPublicKey(),
                directKeySig.getSignature());

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeyRing, t1);
        PGPSignature signature = info.getLatestDirectKeySelfSignature();

        assertNotNull(signature);
        assertEquals(directKeySig, signature);

        assertEquals(SignatureType.DIRECT_KEY, SignatureType.valueOf(signature.getSignatureType()));
        assertEquals(Collections.singletonList(KeyFlag.CERTIFY_OTHER), SignatureSubpacketsUtil.parseKeyFlags(signature));
        assertEquals(Collections.singleton(HashAlgorithm.SHA512), SignatureSubpacketsUtil.parsePreferredHashAlgorithms(signature));
        assertEquals(Collections.singleton(CompressionAlgorithm.ZIP), SignatureSubpacketsUtil.parsePreferredCompressionAlgorithms(signature));
        assertEquals(Collections.singleton(SymmetricKeyAlgorithm.AES_256), SignatureSubpacketsUtil.parsePreferredSymmetricKeyAlgorithms(signature));
        assertEquals(secretKeyRing.getPublicKey().getKeyID(), signature.getKeyID());
        assertArrayEquals(secretKeyRing.getPublicKey().getFingerprint(), signature.getHashedSubPackets().getIssuerFingerprint().getFingerprint());
    }
}
