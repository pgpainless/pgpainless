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
package org.pgpainless.encryption_signing;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;

/**
 * This class is based upon Jens Neuhalfen's Bouncy-GPG PGPEncryptingStream.
 * @see <a href="https://github.com/neuhalje/bouncy-gpg/blob/master/src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/encrypting/PGPEncryptingStream.java">Source</a>
 */
public final class EncryptionStream extends OutputStream {

    private static final Logger LOGGER = Logger.getLogger(EncryptionStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private static final int BUFFER_SIZE = 1 << 8;

    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final Set<PGPPublicKey> encryptionKeys;
    private final Set<PGPPrivateKey> signingKeys;
    private final boolean asciiArmor;

    private final OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();

    private List<PGPSignatureGenerator> signatureGenerators = new ArrayList<>();
    private boolean closed = false;

    OutputStream outermostStream = null;

    private ArmoredOutputStream armorOutputStream = null;
    private OutputStream publicKeyEncryptedStream = null;

    private PGPCompressedDataGenerator compressedDataGenerator;
    private BCPGOutputStream basicCompressionStream;

    private PGPLiteralDataGenerator literalDataGenerator;
    private OutputStream literalDataStream;

    EncryptionStream(@Nonnull OutputStream targetOutputStream,
                     @Nonnull Set<PGPPublicKey> encryptionKeys,
                     @Nonnull Set<PGPPrivateKey> signingKeys,
                     @Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                     @Nonnull HashAlgorithm hashAlgorithm,
                     @Nonnull CompressionAlgorithm compressionAlgorithm,
                     boolean asciiArmor)
            throws IOException, PGPException {

        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.encryptionKeys = Collections.unmodifiableSet(encryptionKeys);
        this.signingKeys = Collections.unmodifiableSet(signingKeys);
        this.asciiArmor = asciiArmor;

        outermostStream = targetOutputStream;
        prepareArmor();
        prepareEncryption();
        prepareSigning();
        prepareCompression();
        prepareOnePassSignatures();
        prepareLiteralDataProcessing();
        prepareResultBuilder();
    }

    private void prepareArmor() {
        if (!asciiArmor) {
            LOGGER.log(LEVEL, "Encryption output will be binary");
            return;
        }

        LOGGER.log(LEVEL, "Wrap encryption output in ASCII armor");
        armorOutputStream = new ArmoredOutputStream(outermostStream);
        outermostStream = armorOutputStream;
    }

    private void prepareEncryption() throws IOException, PGPException {
        if (encryptionKeys.isEmpty()) {
            return;
        }

        LOGGER.log(LEVEL, "At least one encryption key is available -> encrypt using " + symmetricKeyAlgorithm);
        BcPGPDataEncryptorBuilder dataEncryptorBuilder =
                new BcPGPDataEncryptorBuilder(symmetricKeyAlgorithm.getAlgorithmId());

        dataEncryptorBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(dataEncryptorBuilder);

        for (PGPPublicKey key : encryptionKeys) {
            LOGGER.log(LEVEL, "Encrypt for key " + Long.toHexString(key.getKeyID()));
            encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));
        }

        publicKeyEncryptedStream = encryptedDataGenerator.open(outermostStream, new byte[BUFFER_SIZE]);
        outermostStream = publicKeyEncryptedStream;
    }

    private void prepareSigning() throws PGPException {
        if (signingKeys.isEmpty()) {
            return;
        }

        LOGGER.log(LEVEL, "At least one signing key is available -> sign " + hashAlgorithm + " hash of message");
        for (PGPPrivateKey privateKey : signingKeys) {
            LOGGER.log(LEVEL, "Sign using key " + Long.toHexString(privateKey.getKeyID()));
            BcPGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(
                    privateKey.getPublicKeyPacket().getAlgorithm(), hashAlgorithm.getAlgorithmId());

            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
            signatureGenerators.add(signatureGenerator);
        }
    }

    private void prepareCompression() throws IOException {
        LOGGER.log(LEVEL, "Compress using " + compressionAlgorithm);
        compressedDataGenerator = new PGPCompressedDataGenerator(
                compressionAlgorithm.getAlgorithmId());
        basicCompressionStream = new BCPGOutputStream(compressedDataGenerator.open(outermostStream));
    }

    private void prepareOnePassSignatures() throws IOException, PGPException {
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            signatureGenerator.generateOnePassVersion(false).encode(basicCompressionStream);
        }
    }

    private void prepareLiteralDataProcessing() throws IOException {
        literalDataGenerator = new PGPLiteralDataGenerator();
        literalDataStream = literalDataGenerator.open(basicCompressionStream,
                PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, new Date(), new byte[BUFFER_SIZE]);
    }

    private void prepareResultBuilder() {
        for (PGPPublicKey recipient : encryptionKeys) {
            resultBuilder.addRecipientKeyId(recipient.getKeyID());
        }
        resultBuilder.setSymmetricKeyAlgorithm(symmetricKeyAlgorithm);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);
    }

    @Override
    public void write(int data) throws IOException {
        literalDataStream.write(data);

        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            byte asByte = (byte) (data & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(byte[] buffer, int off, int len) throws IOException {
        literalDataStream.write(buffer, 0, len);
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void flush() throws IOException {
        literalDataStream.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        // Literal Data
        literalDataStream.flush();
        literalDataStream.close();
        literalDataGenerator.close();

        writeSignatures();

        // Compressed Data
        compressedDataGenerator.close();

        // Public Key Encryption
        if (publicKeyEncryptedStream != null) {
            publicKeyEncryptedStream.flush();
            publicKeyEncryptedStream.close();
        }

        // Armor
        if (armorOutputStream != null) {
            armorOutputStream.flush();
            armorOutputStream.close();
        }
        closed = true;
    }

    private void writeSignatures() throws IOException {
        for (PGPSignatureGenerator signatureGenerator : signatureGenerators) {
            try {
                PGPSignature signature = signatureGenerator.generate();
                signature.encode(basicCompressionStream);
                resultBuilder.addSignature(signature);
                resultBuilder.addUnverifiedSignatureKeyId(signature.getKeyID());
            } catch (PGPException e) {
                throw new IOException(e);
            }
        }
    }

    public OpenPgpMetadata getResult() {
        if (!closed) {
            throw new IllegalStateException("EncryptionStream must be closed before accessing the Result.");
        }
        return resultBuilder.build();
    }
}
