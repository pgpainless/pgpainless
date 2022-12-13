// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.KeyIntegrityException;
import org.pgpainless.implementation.ImplementationFactory;

/**
 * Utility class to verify keys against Key Overwriting (KO) attacks.
 * This class of attacks is only possible if the attacker has access to the (encrypted) secret key material.
 * To execute the attack, they would modify the unauthenticated parameters of the users public key.
 * Using the modified public key in combination with the unmodified secret key material can then lead to the
 * extraction of secret key parameters via weakly crafted messages.
 *
 * @see <a href="https://www.kopenpgp.com/">Key Overwriting (KO) Attacks against OpenPGP</a>
 */
public class PublicKeyParameterValidationUtil {

    public static void verifyPublicKeyParameterIntegrity(PGPPrivateKey privateKey, PGPPublicKey publicKey)
            throws KeyIntegrityException {
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.requireFromId(publicKey.getAlgorithm());
        boolean valid = true;

        // Algorithm specific validations
        BCPGKey key = privateKey.getPrivateKeyDataPacket();
        if (key instanceof RSASecretBCPGKey) {
            valid = verifyRSAKeyIntegrity(
                    (RSASecretBCPGKey) key,
                    (RSAPublicBCPGKey) publicKey.getPublicKeyPacket().getKey())
                    && valid;
        } else if (key instanceof EdSecretBCPGKey) {
            valid = verifyEdDsaKeyIntegrity(
                    (EdSecretBCPGKey) key,
                    (EdDSAPublicBCPGKey) publicKey.getPublicKeyPacket().getKey())
                    && valid;
        } else if (key instanceof DSASecretBCPGKey) {
            valid = verifyDsaKeyIntegrity(
                    (DSASecretBCPGKey) key,
                    (DSAPublicBCPGKey) publicKey.getPublicKeyPacket().getKey())
                    && valid;
        } else if (key instanceof ElGamalSecretBCPGKey) {
            valid = verifyElGamalKeyIntegrity(
                    (ElGamalSecretBCPGKey) key,
                    (ElGamalPublicBCPGKey) publicKey.getPublicKeyPacket().getKey())
                    && valid;
        }

        if (!valid) {
            throw new KeyIntegrityException();
        }

        // Additional to the algorithm-specific tests further above, we also perform
        // generic functionality tests with the key, such as whether it is able to decrypt encrypted data
        // or verify signatures.
        // These tests should be more or less constant time.
        if (publicKeyAlgorithm.isSigningCapable()) {
            valid = verifyCanSign(privateKey, publicKey);
        }
        if (publicKeyAlgorithm.isEncryptionCapable()) {
            valid = verifyCanDecrypt(privateKey, publicKey) && valid;
        }

        if (!valid) {
            throw new KeyIntegrityException();
        }
    }

    /**
     * Verify that the public key can be used to successfully verify a signature made by the private key.
     * @param privateKey private key
     * @param publicKey public key
     * @return false if signature verification fails
     */
    private static boolean verifyCanSign(PGPPrivateKey privateKey, PGPPublicKey publicKey) {
        SecureRandom random = new SecureRandom();
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.requireFromId(publicKey.getAlgorithm());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(publicKeyAlgorithm, HashAlgorithm.SHA256)
        );

        try {
            signatureGenerator.init(SignatureType.TIMESTAMP.getCode(), privateKey);

            byte[] data = new byte[512];
            random.nextBytes(data);

            signatureGenerator.update(data);
            PGPSignature sig = signatureGenerator.generate();

            sig.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), publicKey);
            sig.update(data);
            return sig.verify();
        } catch (PGPException e) {
            return false;
        }
    }

    /**
     * Verify that the public key can be used to encrypt a message which can successfully be
     * decrypted using the private key.
     * @param privateKey private key
     * @param publicKey public key
     * @return false if decryption of a message encrypted with the public key fails
     */
    private static boolean verifyCanDecrypt(PGPPrivateKey privateKey, PGPPublicKey publicKey) {
        SecureRandom random = new SecureRandom();
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                ImplementationFactory.getInstance().getPGPDataEncryptorBuilder(SymmetricKeyAlgorithm.AES_256)
        );
        encryptedDataGenerator.addMethod(
                ImplementationFactory.getInstance().getPublicKeyKeyEncryptionMethodGenerator(publicKey));

        byte[] data = new byte[1024];
        random.nextBytes(data);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            OutputStream outputStream = encryptedDataGenerator.open(out, new byte[1024]);
            outputStream.write(data);
            encryptedDataGenerator.close();
            PGPEncryptedDataList encryptedDataList = new PGPEncryptedDataList(out.toByteArray());
            PublicKeyDataDecryptorFactory decryptorFactory =
                    ImplementationFactory.getInstance().getPublicKeyDataDecryptorFactory(privateKey);
            PGPPublicKeyEncryptedData encryptedData =
                    (PGPPublicKeyEncryptedData) encryptedDataList.getEncryptedDataObjects().next();
            InputStream decrypted = encryptedData.getDataStream(decryptorFactory);
            out = new ByteArrayOutputStream();
            Streams.pipeAll(decrypted, out);
            decrypted.close();
        } catch (IOException | PGPException e) {
            return false;
        }

        return Arrays.constantTimeAreEqual(data, out.toByteArray());
    }

    private static boolean verifyEdDsaKeyIntegrity(EdSecretBCPGKey privateKey, EdDSAPublicBCPGKey publicKey)
            throws KeyIntegrityException {
        // TODO: Implement
        return true;
    }

    private static boolean verifyDsaKeyIntegrity(DSASecretBCPGKey privateKey, DSAPublicBCPGKey publicKey)
            throws KeyIntegrityException {
        // Not sure what value to put here in order to have a "robust" primality check
        // I went with 40, since that's what SO recommends:
        // https://stackoverflow.com/a/6330138
        final int certainty = 40;
        BigInteger pG = publicKey.getG();
        BigInteger pP = publicKey.getP();
        BigInteger pQ = publicKey.getQ();
        BigInteger pY = publicKey.getY();
        BigInteger sX = privateKey.getX();

        boolean pPrime = pP.isProbablePrime(certainty);
        if (!pPrime) {
            return false;
        }

        boolean qPrime = pQ.isProbablePrime(certainty);
        if (!qPrime) {
            return false;
        }

        // q > 160 bits
        boolean qLarge = pQ.bitLength() > 160;
        if (!qLarge) {
            return false;
        }

        // q divides p - 1
        boolean qDividesPminus1 = pP.subtract(BigInteger.ONE).mod(pQ).equals(BigInteger.ZERO);
        if (!qDividesPminus1) {
            return false;
        }

        // 1 < g < p
        boolean gInBounds = BigInteger.ONE.max(pG).equals(pG) && pG.max(pP).equals(pP);
        if (!gInBounds) {
            return false;
        }

        // g^q = 1 mod p
        boolean gPowXModPEquals1 = pG.modPow(pQ, pP).equals(BigInteger.ONE);
        if (!gPowXModPEquals1) {
            return false;
        }

        // y = g^x mod p
        boolean yEqualsGPowXModP = pY.equals(pG.modPow(sX, pP));
        if (!yEqualsGPowXModP) {
            return false;
        }

        return true;
    }

    private static boolean verifyRSAKeyIntegrity(RSASecretBCPGKey secretKey, RSAPublicBCPGKey publicKey)
            throws KeyIntegrityException {
        // Verify that the public keys N is equal to private keys p*q
        return publicKey.getModulus().equals(secretKey.getPrimeP().multiply(secretKey.getPrimeQ()));
    }

    /**
     * Validate ElGamal public key parameters.
     *
     * Original implementation by the openpgpjs authors:
     * <a href="https://github.com/openpgpjs/openpgpjs/blob/main/src/crypto/public_key/elgamal.js#L76-L143>OpenPGP.js source</a>
     * @param secretKey secret key
     * @param publicKey public key
     * @return true if supposedly valid, false if invalid
     */
    private static boolean verifyElGamalKeyIntegrity(ElGamalSecretBCPGKey secretKey, ElGamalPublicBCPGKey publicKey) {
        BigInteger p = publicKey.getP();
        BigInteger g = publicKey.getG();
        BigInteger y = publicKey.getY();
        BigInteger one = BigInteger.ONE;

        // 1 < g < p
        if (g.min(one).equals(g) || g.max(p).equals(g)) {
            return false;
        }

        // p-1 is large
        if (p.bitLength() < 1023) {
            return false;
        }

        // g^(p-1) mod p = 1
        if (!g.modPow(p.subtract(one), p).equals(one)) {
            return false;
        }

        // check g^i mod p != 1 for i < threshold
        BigInteger res = g;
        BigInteger i = BigInteger.valueOf(1);
        BigInteger threshold = BigInteger.valueOf(2).shiftLeft(17);
        while (i.compareTo(threshold) < 0) {
            res = res.multiply(g).mod(p);
            if (res.equals(one)) {
                return false;
            }
            i = i.add(one);
        }

        // blinded exponentiation to check y = g^(r*(p-1)+x) mod p
        SecureRandom random = new SecureRandom();
        BigInteger x = secretKey.getX();
        BigInteger r = new BigInteger(p.bitLength(), random);
        BigInteger rqx = p.subtract(one).multiply(r).add(x);
        if (!y.equals(g.modPow(rqx, p))) {
            return false;
        }

        return true;
    }

}
