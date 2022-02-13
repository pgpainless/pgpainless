// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.generation.KeyRingTemplates;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.parsing.KeyRingReader;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.ArmoredOutputStreamFactory;

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
     * Wrap a key or certificate in ASCII armor.
     *
     * @param key key or certificate
     * @return ascii armored string
     */
    public static String asciiArmor(@Nonnull PGPKeyRing key) throws IOException {
        if (key instanceof PGPSecretKeyRing) {
            return ArmorUtils.toAsciiArmoredString((PGPSecretKeyRing) key);
        } else {
            return ArmorUtils.toAsciiArmoredString((PGPPublicKeyRing) key);
        }
    }

    public static String asciiArmor(@Nonnull PGPSignature signature) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = ArmoredOutputStreamFactory.get(byteOut);
        BCPGOutputStream bcpgOut = new BCPGOutputStream(armoredOut, true);
        signature.encode(bcpgOut);
        bcpgOut.close();
        armoredOut.close();
        return byteOut.toString();
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
        return new SecretKeyRingEditor(secretKeys);
    }

    /**
     * Quickly access information about a {@link org.bouncycastle.openpgp.PGPPublicKeyRing} / {@link PGPSecretKeyRing}.
     * This method can be used to determine expiration dates, key flags and other information about a key.
     *
     * To evaluate a key at a given date (e.g. to determine if the key was allowed to create a certain signature)
     * use {@link KeyRingInfo#KeyRingInfo(PGPKeyRing, Date)} instead.
     *
     * @param keyRing key ring
     * @return access object
     */
    public static KeyRingInfo inspectKeyRing(PGPKeyRing keyRing) {
        return new KeyRingInfo(keyRing);
    }

    /**
     * Access, and make changes to PGPainless policy on acceptable/default algorithms etc.
     *
     * @return policy
     */
    public static Policy getPolicy() {
        return Policy.getInstance();
    }
}
