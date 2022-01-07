// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.signature.SignatureUtils;
import sop.SOP;
import sop.Verification;
import sop.enums.SignAs;
import sop.exception.SOPGPException;

public class SignTest {

    private static SOP sop;
    private static byte[] key;
    private static byte[] cert;
    private static byte[] data;

    @BeforeAll
    public static void setup() throws IOException {
        sop = new SOPImpl();
        key = sop.generateKey()
                .userId("Alice")
                .generate()
                .getBytes();
        cert = sop.extractCert()
                .key(key)
                .getBytes();
        data = "Hello, World\n".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void signArmored() throws IOException {
        byte[] signature = sop.sign()
                .key(key)
                .data(data)
                .toByteArrayAndResult().getBytes();

        assertTrue(new String(signature).startsWith("-----BEGIN PGP SIGNATURE-----"));

        List<Verification> verifications = sop.verify()
                .cert(cert)
                .notAfter(new Date(new Date().getTime() + 10000))
                .notBefore(new Date(new Date().getTime() - 10000))
                .signatures(signature)
                .data(data);

        assertEquals(1, verifications.size());
    }

    @Test
    public void signUnarmored() throws IOException {
        byte[] signature = sop.sign()
                .key(key)
                .noArmor()
                .data(data)
                .toByteArrayAndResult().getBytes();

        assertFalse(new String(signature).startsWith("-----BEGIN PGP SIGNATURE-----"));

        List<Verification> verifications = sop.verify()
                .cert(cert)
                .notAfter(new Date(new Date().getTime() + 10000))
                .notBefore(new Date(new Date().getTime() - 10000))
                .signatures(signature)
                .data(data);

        assertEquals(1, verifications.size());
    }

    @Test
    public void rejectSignatureAsTooOld() throws IOException {
        byte[] signature = sop.sign()
                .key(key)
                .data(data)
                .toByteArrayAndResult().getBytes();

        assertThrows(SOPGPException.NoSignature.class, () -> sop.verify()
                .cert(cert)
                .notAfter(new Date(new Date().getTime() - 10000)) // Sig is older
                .signatures(signature)
                .data(data));
    }

    @Test
    public void rejectSignatureAsTooYoung() throws IOException {
        byte[] signature = sop.sign()
                .key(key)
                .data(data)
                .toByteArrayAndResult().getBytes();

        assertThrows(SOPGPException.NoSignature.class, () -> sop.verify()
                .cert(cert)
                .notBefore(new Date(new Date().getTime() + 10000)) // Sig is younger
                .signatures(signature)
                .data(data));
    }

    @Test
    public void mode() throws IOException, PGPException {
        byte[] signature = sop.sign()
                .mode(SignAs.Text)
                .key(key)
                .data(data)
                .toByteArrayAndResult().getBytes();

        PGPSignature sig = SignatureUtils.readSignatures(signature).get(0);
        assertEquals(SignatureType.CANONICAL_TEXT_DOCUMENT.getCode(), sig.getSignatureType());
    }

    @Test
    public void rejectEncryptedKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing key = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", "passphrase");
        byte[] bytes = key.getEncoded();

        assertThrows(SOPGPException.KeyIsProtected.class, () -> sop.sign().key(bytes));
    }

}
