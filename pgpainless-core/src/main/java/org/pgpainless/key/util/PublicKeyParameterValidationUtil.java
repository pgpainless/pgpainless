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

public class PublicKeyParameterValidationUtil {

    public static void verifyPublicKeyParameterIntegrity(PGPPrivateKey privateKey, PGPPublicKey publicKey)
            throws KeyIntegrityException, PGPException {
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.fromId(publicKey.getAlgorithm());
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
        }

        // TODO: ElGamal

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

    private static boolean verifyCanSign(PGPPrivateKey privateKey, PGPPublicKey publicKey) throws PGPException {
        SecureRandom random = new SecureRandom();
        PublicKeyAlgorithm publicKeyAlgorithm = PublicKeyAlgorithm.fromId(publicKey.getAlgorithm());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(publicKeyAlgorithm, HashAlgorithm.SHA256)
        );

        signatureGenerator.init(SignatureType.TIMESTAMP.getCode(), privateKey);

        byte[] data = new byte[512];
        random.nextBytes(data);

        signatureGenerator.update(data);
        PGPSignature sig = signatureGenerator.generate();

        sig.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), publicKey);
        sig.update(data);
        return sig.verify();
    }

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
        boolean qLarge = pQ.getLowestSetBit() > 160;
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
}
