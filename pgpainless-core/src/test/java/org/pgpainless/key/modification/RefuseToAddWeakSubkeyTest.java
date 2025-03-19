// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.EnumMap;
import java.util.Map;

import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.Passphrase;

public class RefuseToAddWeakSubkeyTest {

    @Test
    public void testEditorRefusesToAddWeakSubkey() {
        PGPainless api = PGPainless.getInstance();
        // ensure default policy is set
        Policy oldPolicy = api.getAlgorithmPolicy();
        Policy adjusted = oldPolicy.copy().withPublicKeyAlgorithmPolicy(
                Policy.PublicKeyAlgorithmPolicy.bsi2021PublicKeyAlgorithmPolicy()
        ).build();
        api.setAlgorithmPolicy(adjusted);

        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("Alice");
        SecretKeyRingEditorInterface editor = api.modify(secretKeys);
        KeySpec spec = KeySpec.getBuilder(KeyType.RSA(RsaLength._1024), KeyFlag.ENCRYPT_COMMS).build();

        assertThrows(IllegalArgumentException.class, () ->
                editor.addSubKey(spec, Passphrase.emptyPassphrase(), SecretKeyRingProtector.unprotectedKeys()));
        api.setAlgorithmPolicy(oldPolicy);
    }

    @Test
    public void testEditorAllowsToAddWeakSubkeyIfCompliesToPublicKeyAlgorithmPolicy() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("Alice");

        Policy oldPolicy = api.getAlgorithmPolicy();

        // set weak policy
        Map<PublicKeyAlgorithm, Integer> minimalBitStrengths = new EnumMap<>(PublicKeyAlgorithm.class);
        // §5.4.1
        minimalBitStrengths.put(PublicKeyAlgorithm.RSA_GENERAL, 1024);
        minimalBitStrengths.put(PublicKeyAlgorithm.RSA_SIGN, 1024);
        minimalBitStrengths.put(PublicKeyAlgorithm.RSA_ENCRYPT, 1024);
        // Note: ElGamal is not mentioned in the BSI document.
        //  We assume that the requirements are similar to other DH algorithms
        minimalBitStrengths.put(PublicKeyAlgorithm.ELGAMAL_ENCRYPT, 2000);
        minimalBitStrengths.put(PublicKeyAlgorithm.ELGAMAL_GENERAL, 2000);
        // §5.4.2
        minimalBitStrengths.put(PublicKeyAlgorithm.DSA, 2000);
        // §5.4.3
        minimalBitStrengths.put(PublicKeyAlgorithm.ECDSA, 250);
        // Note: EdDSA is not mentioned in the BSI document.
        //  We assume that the requirements are similar to other EC algorithms.
        minimalBitStrengths.put(PublicKeyAlgorithm.EDDSA_LEGACY, 250);
        // §7.2.1
        minimalBitStrengths.put(PublicKeyAlgorithm.DIFFIE_HELLMAN, 2000);
        // §7.2.2
        minimalBitStrengths.put(PublicKeyAlgorithm.ECDH, 250);
        api.setAlgorithmPolicy(oldPolicy.copy()
                .withPublicKeyAlgorithmPolicy(new Policy.PublicKeyAlgorithmPolicy(minimalBitStrengths))
                .build());

        SecretKeyRingEditorInterface editor = api.modify(secretKeys);
        KeySpec spec = KeySpec.getBuilder(KeyType.RSA(RsaLength._1024), KeyFlag.ENCRYPT_COMMS)
                .setKeyCreationDate(editor.getReferenceTime()) // The key gets created after we instantiate the editor.
                .build();

        secretKeys = editor.addSubKey(spec, Passphrase.emptyPassphrase(), SecretKeyRingProtector.unprotectedKeys())
                .done();

        assertEquals(2, api.inspect(secretKeys).getEncryptionSubkeys(EncryptionPurpose.ANY).size());

        // reset default policy
        api.setAlgorithmPolicy(oldPolicy);
    }
}
