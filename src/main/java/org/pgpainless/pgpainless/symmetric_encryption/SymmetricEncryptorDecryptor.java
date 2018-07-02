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
package org.pgpainless.pgpainless.symmetric_encryption;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;

/**
 * Stolen from <a href="https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/PBEFileProcessor.java">
 *     Bouncycastle examples</a>.
 */
public class SymmetricEncryptorDecryptor {

    /**
     * Encrypt some {@code data} symmetrically using an {@code encryptionAlgorithm} and a given {@code password}.
     * The input data will be compressed using the given {@code compressionAlgorithm} and packed in a modification
     * detection package, which is then encrypted.
     *
     * @param data bytes that will be encrypted
     * @param password password that will be used to encrypt the data
     * @param encryptionAlgorithm symmetric algorithm that will be used to encrypt the data
     * @param compressionAlgorithm compression algorithm that will be used to compress the data
     * @return encrypted data
     * @throws IOException IO is dangerous
     * @throws PGPException OpenPGP is brittle
     */
    public static byte[] symmetricallyEncrypt(byte[] data,
                                              char[] password,
                                              SymmetricKeyAlgorithm encryptionAlgorithm,
                                              CompressionAlgorithm compressionAlgorithm)
            throws IOException, PGPException {

        byte[] compressedData = compress(data, compressionAlgorithm.getAlgorithmId());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(encryptionAlgorithm.getAlgorithmId())
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password).setProvider("BC"));

        OutputStream encOut = encGen.open(bOut, compressedData.length);

        encOut.write(compressedData);
        encOut.close();

        return bOut.toByteArray();
    }

    /**
     * Decrypt and decompress some symmetrically encrypted data using a password.
     * Note, that decryption will fail if the given data is not integrity protected with a modification detection
     * package.
     *
     * @param data encrypted data
     * @param password password to decrypt the data
     * @return decrypted data
     * @throws IOException IO is dangerous
     * @throws PGPException OpenPGP is brittle
     */
    public static byte[] symmetricallyDecrypt(byte[] data, char[] password) throws IOException, PGPException {
        InputStream in = new BufferedInputStream(new ByteArrayInputStream(data));
        in = PGPUtil.getDecoderStream(in);

        BcPGPObjectFactory pgpF = new BcPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) enc.get(0);

        InputStream clear = pbe.getDataStream(new BcPBEDataDecryptorFactory(
                password, new BcPGPDigestCalculatorProvider()));


        BcPGPObjectFactory pgpFact = new BcPGPObjectFactory(clear);

        o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData   cData = (PGPCompressedData) o;
            pgpFact = new BcPGPObjectFactory(cData.getDataStream());
            o = pgpFact.nextObject();
        }

        PGPLiteralData ld = (PGPLiteralData) o;
        InputStream unc = ld.getInputStream();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Streams.pipeAll(unc, outputStream);

        outputStream.close();

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Integrity check failed.");
            }
        } else {
            throw new PGPException("Symmetrically encrypted data is not integrity protected.");
        }

        return outputStream.toByteArray();
    }

    /**
     * Wrap some data in an OpenPGP compressed data package.
     *
     * @param clearData uncompressed data
     * @param algorithm compression algorithm
     * @return compressed data
     * @throws IOException IO is dangerous
     */
    private static byte[] compress(byte[] clearData, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        OutputStream cos = comData.open(bOut);

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream  pOut = lData.open(cos,
                PGPLiteralData.BINARY,
                PGPLiteralDataGenerator.CONSOLE,
                clearData.length,
                new Date()
        );

        pOut.write(clearData);
        pOut.close();

        comData.close();

        return bOut.toByteArray();
    }

}
