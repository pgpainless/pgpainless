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

import java.util.Date;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.decryption_verification.DecryptionBuilder;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.encryption_signing.EncryptionBuilder;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.generation.KeyRingBuilder;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.parsing.KeyRingReader;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.cleartext_signatures.VerifyCleartextSignatures;
import org.pgpainless.signature.cleartext_signatures.VerifyCleartextSignaturesImpl;

public class PGPainless {

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
     * Create an {@link EncryptionStream}, which can be used to encrypt and/or sign data using OpenPGP.
     *
     * @deprecated Use {@link #encryptAndOrSign()} instead.
     * @return builder
     */
    @Deprecated
    public static EncryptionBuilder createEncryptor() {
        return encryptAndOrSign();
    }

    /**
     * Create an {@link EncryptionStream}, which can be used to encrypt and/or sign data using OpenPGP.
     * This method assumes that the stream will be used to encrypt data for communication purposes.
     * If you instead want to encrypt data that will be saved on disk (eg. a backup), use
     * {@link #encryptAndOrSign(EncryptionPurpose)} and chose an appropriate purpose.
     *
     * @return builder
     */
    public static EncryptionBuilder encryptAndOrSign() {
        return new EncryptionBuilder();
    }

    /**
     * Create an {@link EncryptionStream}, that can be used to encrypt and/or sign data using OpenPGP.
     *
     * @param purpose how will the data be used?
     * @return builder
     * @deprecated use {@link #encryptAndOrSign()} and set the purpose in
     * {@link org.pgpainless.encryption_signing.EncryptionOptions} instead
     */
    public static EncryptionBuilder encryptAndOrSign(EncryptionPurpose purpose) {
        return new EncryptionBuilder(purpose);
    }

    /**
     * Create a {@link DecryptionStream}, which can be used to decrypt and/or verify data using OpenPGP.
     *
     * @deprecated Use {@link #decryptAndOrVerify()} instead.
     * @return builder
     */
    @Deprecated
    public static DecryptionBuilder createDecryptor() {
        return decryptAndOrVerify();
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
