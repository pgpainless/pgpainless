// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashMap;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.NotationRegistry;

/**
 * PGPainless comes with an algorithm policy.
 * This policy is consulted during signature verification, such that signatures made using weak algorithms
 * can be rejected.
 * Note, that PGPainless distinguishes between hash algorithms used in revocation and non-revocation signatures,
 * and has different policies for those.
 * <p>
 * Furthermore, PGPainless has policies for symmetric encryption algorithms (both for encrypting and decrypting),
 * for public key algorithms and key lengths, as well as compression algorithms.
 * <p>
 * The following examples show how these policies can be modified.
 * <p>
 * PGPainless' policy is being accessed by calling {@link PGPainless#getAlgorithmPolicy()}.
 * Custom sub-policies can be set by calling the setter methods of {@link Policy}.
 */
public class ManagePolicy {

    /**
     * Reset PGPainless' policy class to default values.
     */
    @BeforeEach
    @AfterEach
    public void resetPolicy() {
        // Policy for hash algorithms in non-revocation signatures
        PGPainless.getInstance().setAlgorithmPolicy(new Policy());
    }

    /**
     * {@link HashAlgorithm Hash Algorithms} may get outdated with time. {@link HashAlgorithm#SHA1} is a prominent
     * example for an algorithm that is nowadays considered unsafe to use and which shall be avoided.
     * <p>
     * PGPainless comes with a {@link Policy} class that defines which algorithms are trustworthy and acceptable.
     * It also allows the user to specify a custom policy tailored to their needs.
     * <p>
     * Per default, PGPainless will reject non-revocation signatures that use SHA-1 as hash algorithm.
     * To inspect PGPainless' default signature hash algorithm policy, see
     * {@link Policy.HashAlgorithmPolicy#static2022SignatureHashAlgorithmPolicy()}.
     * <p>
     * Since it may be a valid use-case to accept signatures made using SHA-1 as part of a less strict policy,
     * this example demonstrates how to set a custom signature hash algorithm policy.
     */
    @Test
    public void setCustomSignatureHashPolicy() {
        // Get PGPainless' policy
        Policy oldPolicy = PGPainless.getInstance().getAlgorithmPolicy();

        Policy.HashAlgorithmPolicy sigHashAlgoPolicy = oldPolicy.getDataSignatureHashAlgorithmPolicy();
        assertTrue(sigHashAlgoPolicy.isAcceptable(HashAlgorithm.SHA512));
        // Per default, non-revocation signatures using SHA-1 are rejected
        assertFalse(sigHashAlgoPolicy.isAcceptable(HashAlgorithm.SHA1));

        // Create a new custom policy which contains SHA-1
        Policy.HashAlgorithmPolicy customPolicy = new Policy.HashAlgorithmPolicy(
                // The default hash algorithm will be used when hash algorithm negotiation fails when creating a sig
                HashAlgorithm.SHA512,
                // List of acceptable hash algorithms
                Arrays.asList(HashAlgorithm.SHA512, HashAlgorithm.SHA384, HashAlgorithm.SHA256, HashAlgorithm.SHA224, HashAlgorithm.SHA1));
        // Set the hash algo policy as policy for non-revocation signatures
        PGPainless.getInstance().setAlgorithmPolicy(
                oldPolicy.copy().withDataSignatureHashAlgorithmPolicy(customPolicy).build()
        );

        sigHashAlgoPolicy = PGPainless.getInstance().getAlgorithmPolicy().getDataSignatureHashAlgorithmPolicy();
        assertTrue(sigHashAlgoPolicy.isAcceptable(HashAlgorithm.SHA512));
        // SHA-1 is now acceptable as well
        assertTrue(sigHashAlgoPolicy.isAcceptable(HashAlgorithm.SHA1));

        // reset old policy
        PGPainless.getInstance().setAlgorithmPolicy(oldPolicy);
    }

    /**
     * Similar to hash algorithms, {@link PublicKeyAlgorithm PublicKeyAlgorithms} tend to get outdated eventually.
     * Per default, PGPainless will reject signatures made by keys of unacceptable algorithm or length.
     * See {@link Policy.PublicKeyAlgorithmPolicy#bsi2021PublicKeyAlgorithmPolicy()}
     * to inspect PGPainless' defaults.
     * <p>
     * This example demonstrates how to set a custom public key algorithm policy.
     */
    @Test
    public void setCustomPublicKeyAlgorithmPolicy() {
        Policy oldPolicy = PGPainless.getInstance().getAlgorithmPolicy();
        Policy.PublicKeyAlgorithmPolicy pkAlgorithmPolicy = oldPolicy.getPublicKeyAlgorithmPolicy();
        assertTrue(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 4096));
        assertTrue(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 2048));
        assertFalse(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 1024));
        assertTrue(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.ECDSA, 256));

        Policy.PublicKeyAlgorithmPolicy customPolicy = new Policy.PublicKeyAlgorithmPolicy(
                new HashMap<PublicKeyAlgorithm, Integer>(){{
                    // Put minimum bit strengths for acceptable algorithms.
                    // A key is being rejected if it is not listed in the map,
                    // or its length is smaller than the corresponding minimum
                    put(PublicKeyAlgorithm.RSA_GENERAL, 3000);
                }}
        );
        PGPainless.getInstance().setAlgorithmPolicy(oldPolicy.copy().withPublicKeyAlgorithmPolicy(customPolicy).build());

        pkAlgorithmPolicy = PGPainless.getInstance().getAlgorithmPolicy().getPublicKeyAlgorithmPolicy();
        assertTrue(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 4096));
        // RSA 2048 is no longer acceptable
        assertFalse(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.RSA_GENERAL, 2048));
        // ECDSA is no longer acceptable, since it is no longer included in the policy at all
        assertFalse(pkAlgorithmPolicy.isAcceptable(PublicKeyAlgorithm.ECDSA, 256));

        // Reset policy
        PGPainless.getInstance().setAlgorithmPolicy(oldPolicy);
    }

    /**
     * OpenPGP requires implementations to reject signatures which contain critical notation data subpackets
     * which are not known to the implementation.
     * <p>
     * PGPainless allows the user to define which notations should be considered known notations.
     * The following example demonstrates how to mark the notation value 'unknown@pgpainless.org' as known,
     * such that signatures containing a critical notation with that name are no longer being invalidated because of it.
     */
    @Test
    public void manageKnownNotations() {
        Policy policy = PGPainless.getInstance().getAlgorithmPolicy();
        NotationRegistry notationRegistry = policy.getNotationRegistry();
        assertFalse(notationRegistry.isKnownNotation("unknown@pgpainless.org"));

        notationRegistry.addKnownNotation("unknown@pgpainless.org");

        assertTrue(notationRegistry.isKnownNotation("unknown@pgpainless.org"));
    }
}
