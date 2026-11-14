// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.weird_keys;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;

public class TestEncryptCommsStorageFlagsDifferentiated {

    @Test
    public void testThatEncryptionDifferentiatesBetweenPurposeKeyFlags() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.buildKey()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072),
                                KeyFlag.CERTIFY_OTHER,
                                KeyFlag.SIGN_DATA,
                                KeyFlag.ENCRYPT_STORAGE // no ENCRYPT_COMMS
                        ))
                .addUserId("cannot@encrypt.comms")
                .build();

        OpenPGPCertificate publicKeys = secretKeys.toCertificate();

        assertThrows(KeyException.UnacceptableEncryptionKeyException.class, () -> EncryptionOptions.encryptCommunications(api)
                .addRecipient(publicKeys));
    }
}
