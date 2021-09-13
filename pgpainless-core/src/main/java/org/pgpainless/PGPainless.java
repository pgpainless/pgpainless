/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless;

import java.io.IOException;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.parsing.KeyRingReader;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.policy.Policy;
import org.pgpainless.decryption_verification.cleartext_signatures.VerifyCleartextSignatures;
import org.pgpainless.decryption_verification.cleartext_signatures.VerifyCleartextSignaturesImpl;
import org.pgpainless.util.ArmorUtils;

public final class PGPainless {

    private PGPainless() {

    }

    /**
     * Generate a new OpenPGP key ring.
     * @return builder
     */
    public static KeyRingBuilder generateKeyRing() {
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
     * @throws IOException
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
     * Verify a cleartext-signed message.
     * Cleartext signed messages are often found in emails and look like this:
     * <pre>
     * {@code
     * -----BEGIN PGP SIGNED MESSAGE-----
     * Hash: [Hash algorithm]
     * [Human Readable Message Body]
     * -----BEGIN PGP SIGNATURE-----
     * [Signature]
     * -----END PGP SIGNATURE-----
     * }
     * </pre>
     *
     * @return builder
     */
    public static VerifyCleartextSignatures verifyCleartextSignedMessage() {
        return new VerifyCleartextSignaturesImpl();
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
