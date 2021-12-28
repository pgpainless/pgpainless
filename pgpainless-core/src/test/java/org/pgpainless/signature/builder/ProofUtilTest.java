// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.builder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.consumer.ProofUtil;

public class ProofUtilTest {

    @Test
    public void testEmptyProofThrows() {
        assertThrows(IllegalArgumentException.class, () -> new ProofUtil.Proof(""));
    }

    @Test
    public void testNullProofThrows() {
        assertThrows(IllegalArgumentException.class, () -> new ProofUtil.Proof(null));
    }

    @Test
    public void proofIsTrimmed() {
        ProofUtil.Proof proof = new ProofUtil.Proof("    foo:bar ");
        assertEquals("proof@metacode.biz=foo:bar", proof.toString());
    }

    @Test
    public void testMatrixProof() {
        String matrixUser = "@foo:matrix.org";
        String permalink = "https://matrix.to/#/!dBfQZxCoGVmSTujfiv:matrix.org/$3dVX1nv3lmwnKxc0mgto_Sf-REVr45Z6G7LWLWal10w?via=chat.matrix.org";
        ProofUtil.Proof proof = ProofUtil.Proof.fromMatrixPermalink(matrixUser, permalink);

        assertEquals("proof@metacode.biz=matrix:u/@foo:matrix.org?org.keyoxide.r=!dBfQZxCoGVmSTujfiv:matrix.org&org.keyoxide.e=$3dVX1nv3lmwnKxc0mgto_Sf-REVr45Z6G7LWLWal10w",
                proof.toString());
    }

    @Test
    public void testXmppBasicProof() {
        String jid = "alice@pgpainless.org";
        ProofUtil.Proof proof = new ProofUtil.Proof("xmpp:" + jid);

        assertEquals("proof@metacode.biz=xmpp:alice@pgpainless.org", proof.toString());
    }

    @Test
    public void testAddProof()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        String userId = "Alice <alice@pgpainless.org>";
        PGPSecretKeyRing secretKey = PGPainless.generateKeyRing()
                .modernKeyRing(userId, null);
        Thread.sleep(1000L);
        secretKey = new ProofUtil().addProof(
                secretKey,
                SecretKeyRingProtector.unprotectedKeys(),
                new ProofUtil.Proof("xmpp:alice@pgpainless.org"));

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        PGPSignature signature = info.getLatestUserIdCertification(userId);
        assertNotNull(signature);
        assertFalse(ProofUtil.getProofs(signature).isEmpty());
    }
}
