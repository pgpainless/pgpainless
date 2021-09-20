/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

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

        policy.setSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512,
                Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256)));

        policy.setRevocationSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA512,
                Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256, HashAlgorithm.SHA224, HashAlgorithm.SHA1)));

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
    }

    @Test
    public void testUnacceptableSignatureHashAlgorithm() {
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1));
        assertFalse(policy.getSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA1.getAlgorithmId()));
    }

    @Test
    public void testDefaultSignatureHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA512, policy.getSignatureHashAlgorithmPolicy().defaultHashAlgorithm());
    }

    @Test
    public void testAcceptableRevocationSignatureHashAlgorithm() {
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384));
        assertTrue(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.SHA384.getAlgorithmId()));
    }

    @Test
    public void testUnacceptableRevocationSignatureHashAlgorithm() {
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160));
        assertFalse(policy.getRevocationSignatureHashAlgorithmPolicy().isAcceptable(HashAlgorithm.RIPEMD160.getAlgorithmId()));
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
}
