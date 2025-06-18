// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenPGPCertificateUtilTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncodeSingleCert() {
        PGPainless api = PGPainless.getInstance();

        List<OpenPGPCertificate> certs = new ArrayList<>();
        certs.add(api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>").toCertificate());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPCertificateUtil.armor(certs, bOut, PacketFormat.CURRENT);
        String armor = bOut.toString();

        assertTrue(armor.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: "),
                "For a single cert, the ASCII armor MUST contain a comment with the fingerprint");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncodeSingleKey() {
        PGPainless api = PGPainless.getInstance();

        List<OpenPGPCertificate> certs = new ArrayList<>();
        certs.add(api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>"));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPCertificateUtil.armor(certs, bOut, PacketFormat.CURRENT);
        String armor = bOut.toString();

        assertTrue(armor.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: "),
                "For a single key, the ASCII armor MUST contain a comment with the fingerprint");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncodeTwoCerts() {
        PGPainless api = PGPainless.getInstance();

        List<OpenPGPCertificate> certs = new ArrayList<>();
        certs.add(api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>").toCertificate());
        certs.add(api.generateKey().modernKeyRing("Bob <bob@pgpainless.org>").toCertificate());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPCertificateUtil.armor(certs, bOut, PacketFormat.CURRENT);
        String armor = bOut.toString();

        assertTrue(armor.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertEquals(
                armor.indexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
                armor.lastIndexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
                "There MUST only be a single block in the armor.");
        assertFalse(armor.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: "),
                "For multiple certs, the ASCII armor MUST NOT contain a comment containing the fingerprint");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncodeCertAndKey() {
        PGPainless api = PGPainless.getInstance();

        List<OpenPGPCertificate> certs = new ArrayList<>();
        certs.add(api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>").toCertificate());
        certs.add(api.generateKey().modernKeyRing("Bob <bob@pgpainless.org>"));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPCertificateUtil.armor(certs, bOut, PacketFormat.CURRENT);
        String armor = bOut.toString();

        assertTrue(armor.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertEquals(
                armor.indexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
                armor.lastIndexOf("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assertFalse(armor.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: "),
                "For multiple certs/keys, the ASCII armor MUST NOT contain a comment containing the fingerprint");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncodeKeyAndCert() {
        PGPainless api = PGPainless.getInstance();

        List<OpenPGPCertificate> certs = new ArrayList<>();
        certs.add(api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>"));
        certs.add(api.generateKey().modernKeyRing("Bob <bob@pgpainless.org>").toCertificate());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPCertificateUtil.armor(certs, bOut, PacketFormat.CURRENT);
        String armor = bOut.toString();

        assertTrue(armor.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assertEquals(
                armor.indexOf("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
                armor.lastIndexOf("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assertFalse(armor.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\nComment: "),
                "For multiple certs, the ASCII armor MUST NOT contain a comment containing the fingerprint");
    }
}
