// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.DateUtil;

public class PolicyTest {

    private static Policy policy;

    @BeforeAll
    public static void setup() {
        policy = new Policy();
        policy.setCompressionAlgorithmPolicy(new Policy.CompressionAlgorithmPolicy(CompressionAlgorithm.UNCOMPRESSED,
                Arrays.asList(CompressionAlgorithm.ZIP, CompressionAlgorithm.ZLIB, CompressionAlgorithm.UNCOMPRESSED)));

        policy.setSymmetricKeyEncryptionAlgorithmPolicy(new Policy.SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256,
                Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128)));

        policy.setSymmetricKeyDecryptionAlgorithmPolicy(new Policy.SymmetricKeyAlgorithmPolicy(SymmetricKeyAlgorithm.AES_256,
                Arrays.asList(SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192, SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.BLOWFISH)));

        Map<HashAlgorithm, Date> sigHashAlgoMap = new HashMap<>();
        sigHashAlgoMap.put(HashAlgorithm.SHA512, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA384, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA256, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA224, null);
        sigHashAlgoMap.put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));
        policy.setSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512, sigHashAlgoMap));

        Map<HashAlgorithm, Date> revHashAlgoMap = new HashMap<>();
        revHashAlgoMap.put(HashAlgorithm.SHA512, null);
        revHashAlgoMap.put(HashAlgorithm.SHA384, null);
        revHashAlgoMap.put(HashAlgorithm.SHA256, null);
        revHashAlgoMap.put(HashAlgorithm.SHA224, null);
        revHashAlgoMap.put(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));
        revHashAlgoMap.put(HashAlgorithm.RIPEMD160, DateUtil.parseUTCDate("2013-02-01 00:00:00 UTC"));
        policy.setRevocationSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512,
                revHashAlgoMap));

        policy.setPublicKeyAlgorithmPolicy(Policy.PublicKeyAlgorithmPolicy.defaultPublicKeyAlgorithmPolicy());
    }

    @Test
    public void testAcceptableCompressionAlgorithm() {
        assertTrue(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.ZIP));
        assertTrue(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.ZIP.getAlgorithmId()));
    }

    @Test
    public void testUnacceptableCompressionAlgorithm() {
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.BZIP2));
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(CompressionAlgorithm.BZIP2.getAlgorithmId()));
    }

    @Test
    public void testDefaultCompressionAlgorithm() {
        assertEquals(CompressionAlgorithm.UNCOMPRESSED, policy.getCompressionAlgorithmPolicy().defaultCompressionAlgorithm());
    }

    @Test
    public void testAcceptableSymmetricKeyEncryptionAlgorithm() {
        assertTrue(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.AES_256));
        assertTrue(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.AES_256.getAlgorithmId()));
    }

    @Test
    public void testUnAcceptableSymmetricKeyEncryptionAlgorithm() {
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH));
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH.getAlgorithmId()));
    }

    @Test
    public void testDefaultSymmetricKeyEncryptionAlgorithm() {
        assertEquals(SymmetricKeyAlgorithm.AES_256, policy.getSymmetricKeyEncryptionAlgorithmPolicy().getDefaultSymmetricKeyAlgorithm());
    }

    @Test
    public void testAcceptableSymmetricKeyDecryptionAlgorithm() {
        assertTrue(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH));
        assertTrue(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.BLOWFISH.getAlgorithmId()));
    }

    @Test
    public void testUnAcceptableSymmetricKeyDecryptionAlgorithm() {
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.CAMELLIA_128));
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(SymmetricKeyAlgorithm.CAMELLIA_128.getAlgorithmId()));
    }

    @Test
    public void testAcceptableSignatureHashAlgorithm() {
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA512));
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA512.getAlgorithmId()));
        // Usage date before termination date -> acceptable
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
    }

    @Test
    public void testUnacceptableSignatureHashAlgorithm() {
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId()));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
    }

    @Test
    public void testDefaultSignatureHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA512, policy.getSignatureHashAlgorithmPolicy().defaultHashAlgorithm());
    }

    @Test
    public void testAcceptableRevocationSignatureHashAlgorithm() {
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384));
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384.getAlgorithmId()));
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
        assertTrue(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2000-01-01 00:00:00 UTC")));
    }

    @Test
    public void testUnacceptableRevocationSignatureHashAlgorithm() {
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160));
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160.getAlgorithmId()));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1, DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId(), DateUtil.parseUTCDate("2020-01-01 00:00:00 UTC")));
    }

    @Test
    public void testDefaultRevocationSignatureHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA512, policy.getRevocationSignatureHashAlgorithmPolicy().defaultHashAlgorithm());
    }

    @Test
    public void testAcceptablePublicKeyAlgorithm() {
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA, 256));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.ECDSA.getAlgorithmId(), 256));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 3072));
        assertTrue(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL.getAlgorithmId(), 3072));
    }

    @Test
    public void testUnacceptablePublicKeyAlgorithm() {
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 1024));
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(PublicKeyAlgorithm.RSA_GENERAL.getAlgorithmId(), 1024));
    }

    @Test
    public void testNotationRegistry() {
        assertFalse(policy.getNotationRegistry().isKnownNotation("notation@pgpainless.org"));
        policy.getNotationRegistry().addKnownNotation("notation@pgpainless.org");
        assertTrue(policy.getNotationRegistry().isKnownNotation("notation@pgpainless.org"));
    }

    @Test
    public void testUnknownSymmetricKeyEncryptionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getSymmetricKeyEncryptionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownSymmetricKeyDecryptionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getSymmetricKeyDecryptionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownSignatureHashAlgorithmIsNotAcceptable() {
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(-1));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(-1, new Date()));
    }

    @Test
    public void testUnknownRevocationHashAlgorithmIsNotAcceptable() {
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(-1));
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(-1, new Date()));
    }

    @Test
    public void testUnknownCompressionAlgorithmIsNotAcceptable() {
        assertFalse(policy.getCompressionAlgorithmPolicy().isAcceptable(-1));
    }

    @Test
    public void testUnknownPublicKeyAlgorithmIsNotAcceptable() {
        assertFalse(policy.getPublicKeyAlgorithmPolicy().isAcceptable(-1, 4096));
    }

    @Test
    public void setNullSignerUserIdValidationLevelThrows() {
        assertThrows(NullPointerException.class, () -> policy.setSignerUserIdValidationLevel(null));
    }
}
