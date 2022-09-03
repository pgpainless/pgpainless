// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless;

import java.io.IOException;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.certification.CertifyCertificate;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeyRingTemplates;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.parsing.KeyRingReader;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.ArmorUtils;

public final class PGPainless {

    private PGPainless() {

    }

    /**
     * Generate a fresh OpenPGP key ring from predefined templates.
     * @return templates
     */
    public static KeyRingTemplates generateKeyRing() {
        return new KeyRingTemplates();
    }

    /**
     * Build a custom OpenPGP key ring.
     *
     * @return builder
     */
    public static KeyRingBuilder buildKeyRing() {
        return new KeyRingBuilder();
    }

    /**
     * Read an existing OpenPGP key ring.
     * @return builder
     */
    public static KeyRingReader readKeyRing() {
        return new KeyRingReader();
    }

    /**
     * Extract a public key certificate from a secret key.
     *
     * @param secretKey secret key
     * @return public key certificate
     */
    public static PGPPublicKeyRing extractCertificate(@Nonnull PGPSecretKeyRing secretKey) {
        return KeyRingUtils.publicKeyRingFrom(secretKey);
    }

    /**
     * Merge two copies of the same certificate (e.g. an old copy, and one retrieved from a key server) together.
     *
     * @param originalCopy local, older copy of the cert
     * @param updatedCopy updated, newer copy of the cert
     * @return merged certificate
     * @throws PGPException in case of an error
     */
    public static PGPPublicKeyRing mergeCertificate(
            @Nonnull PGPPublicKeyRing originalCopy,
            @Nonnull PGPPublicKeyRing updatedCopy)
            throws PGPException {
        return PGPPublicKeyRing.join(originalCopy, updatedCopy);
    }

    /**
     * Wrap a key or certificate in ASCII armor.
     *
     * @param key key or certificate
     * @return ascii armored string
     *
     * @throws IOException in case of an error in the {@link org.bouncycastle.bcpg.ArmoredOutputStream}
     */
    public static String asciiArmor(@Nonnull PGPKeyRing key) throws IOException {
        if (key instanceof PGPSecretKeyRing) {
            return ArmorUtils.toAsciiArmoredString((PGPSecretKeyRing) key);
        } else {
            return ArmorUtils.toAsciiArmoredString((PGPPublicKeyRing) key);
        }
    }

    /**
     * Create an {@link EncryptionStream}, which can be used to encrypt and/or sign data using OpenPGP.
     *
     * @return builder
     */
    public static EncryptionBuilder encryptAndOrSign() {
        return new EncryptionBuilder();
    }

    /**
     * Create a {@link DecryptionStream}, which can be used to decrypt and/or verify data using OpenPGP.
     *
     * @return builder
     */
    public static DecryptionBuilder decryptAndOrVerify() {
        return new DecryptionBuilder();
    }

    /**
     * Make changes to a key ring.
     * This method can be used to change key expiration dates and passphrases, or add/remove/revoke subkeys.
     *
     * After making the desired changes in the builder, the modified key ring can be extracted using {@link SecretKeyRingEditorInterface#done()}.
     *
     * @param secretKeys secret key ring
     * @return builder
     */
    public static SecretKeyRingEditorInterface modifyKeyRing(PGPSecretKeyRing secretKeys) {
        return modifyKeyRing(secretKeys, null);
    }

    public static SecretKeyRingEditorInterface modifyKeyRing(PGPSecretKeyRing secretKeys, Date referenceTime) {
        return new SecretKeyRingEditor(secretKeys, referenceTime);
    }

    /**
     * Quickly access information about a {@link org.bouncycastle.openpgp.PGPPublicKeyRing} / {@link PGPSecretKeyRing}.
     * This method can be used to determine expiration dates, key flags and other information about a key.
     *
     * To evaluate a key at a given date (e.g. to determine if the key was allowed to create a certain signature)
     * use {@link #inspectKeyRing(PGPKeyRing, Date)} instead.
     *
     * @param keyRing key ring
     * @return access object
     */
    public static KeyRingInfo inspectKeyRing(PGPKeyRing keyRing) {
        return new KeyRingInfo(keyRing);
    }

    /**
     * Quickly access information about a {@link org.bouncycastle.openpgp.PGPPublicKeyRing} / {@link PGPSecretKeyRing}.
     * This method can be used to determine expiration dates, key flags and other information about a key at a specific time.
     *
     * @param keyRing key ring
     * @param inspectionDate date of inspection
     * @return access object
     */
    public static KeyRingInfo inspectKeyRing(PGPKeyRing keyRing, Date inspectionDate) {
        return new KeyRingInfo(keyRing, inspectionDate);
    }

    /**
     * Access, and make changes to PGPainless policy on acceptable/default algorithms etc.
     *
     * @return policy
     */
    public static Policy getPolicy() {
        return Policy.getInstance();
    }

    /**
     * Create different kinds of signatures on other keys.
     *
     * @return builder
     */
    public static CertifyCertificate certify() {
        return new CertifyCertificate();
    }
}
