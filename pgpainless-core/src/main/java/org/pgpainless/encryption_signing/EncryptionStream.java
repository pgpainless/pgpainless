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

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.util.ArmoredOutputStreamFactory;

/**
 * This class is based upon Jens Neuhalfen's Bouncy-GPG PGPEncryptingStream.
 * @see <a href="https://github.com/neuhalje/bouncy-gpg/blob/master/src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/encrypting/PGPEncryptingStream.java">Source</a>
 */
public final class EncryptionStream extends OutputStream {

    private static final Logger LOGGER = Logger.getLogger(EncryptionStream.class.getName());
    private static final Level LEVEL = Level.FINE;

    private final ProducerOptions options;
    private final EncryptionResult.Builder resultBuilder = EncryptionResult.builder();

    private boolean closed = false;
    private static final int BUFFER_SIZE = 1 << 8;

    OutputStream outermostStream;
    private ArmoredOutputStream armorOutputStream = null;
    private OutputStream publicKeyEncryptedStream = null;
    private PGPCompressedDataGenerator compressedDataGenerator;
    private BCPGOutputStream basicCompressionStream;
    private PGPLiteralDataGenerator literalDataGenerator;
    private OutputStream literalDataStream;

    EncryptionStream(@Nonnull OutputStream targetOutputStream,
                     @Nonnull ProducerOptions options,
                     @Nonnull OpenPgpMetadata.FileInfo fileInfo)
            throws IOException, PGPException {
        this.options = options;
        outermostStream = targetOutputStream;

        prepareArmor();
        prepareEncryption();
        prepareCompression();
        prepareOnePassSignatures();
        prepareLiteralDataProcessing(fileInfo);
    }

    private void prepareArmor() {
        if (!options.isAsciiArmor()) {
            LOGGER.log(LEVEL, "Encryption output will be binary");
            return;
        }

        LOGGER.log(LEVEL, "Wrap encryption output in ASCII armor");
        armorOutputStream = ArmoredOutputStreamFactory.get(outermostStream);
        outermostStream = armorOutputStream;
    }

    private void prepareEncryption() throws IOException, PGPException {
        EncryptionOptions encryptionOptions = options.getEncryptionOptions();
        if (encryptionOptions == null || encryptionOptions.getEncryptionMethods().isEmpty()) {
            // No encryption options/methods -> no encryption
            resultBuilder.setEncryptionAlgorithm(SymmetricKeyAlgorithm.NULL);
            return;
        }

        SymmetricKeyAlgorithm encryptionAlgorithm = EncryptionBuilder.negotiateSymmetricEncryptionAlgorithm(encryptionOptions);
        resultBuilder.setEncryptionAlgorithm(encryptionAlgorithm);
        LOGGER.log(LEVEL, "Encrypt message using " + encryptionAlgorithm);
        PGPDataEncryptorBuilder dataEncryptorBuilder =
                ImplementationFactory.getInstance().getPGPDataEncryptorBuilder(encryptionAlgorithm);
        // Simplify once https://github.com/bcgit/bc-java/pull/859 is merged
        if (dataEncryptorBuilder instanceof BcPGPDataEncryptorBuilder) {
            ((BcPGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        } else if (dataEncryptorBuilder instanceof JcePGPDataEncryptorBuilder) {
            ((JcePGPDataEncryptorBuilder) dataEncryptorBuilder).setWithIntegrityPacket(true);
        }

        PGPEncryptedDataGenerator encryptedDataGenerator =
                new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        for (PGPKeyEncryptionMethodGenerator encryptionMethod : encryptionOptions.getEncryptionMethods()) {
            encryptedDataGenerator.addMethod(encryptionMethod);
        }

        for (SubkeyIdentifier recipientSubkeyIdentifier : encryptionOptions.getEncryptionKeyIdentifiers()) {
            resultBuilder.addRecipient(recipientSubkeyIdentifier);
        }

        publicKeyEncryptedStream = encryptedDataGenerator.open(outermostStream, new byte[BUFFER_SIZE]);
        outermostStream = publicKeyEncryptedStream;
    }

    private void prepareCompression() throws IOException {
        CompressionAlgorithm compressionAlgorithm = EncryptionBuilder.negotiateCompressionAlgorithm(options);
        resultBuilder.setCompressionAlgorithm(compressionAlgorithm);
        compressedDataGenerator = new PGPCompressedDataGenerator(
                compressionAlgorithm.getAlgorithmId());
        if (compressionAlgorithm == CompressionAlgorithm.UNCOMPRESSED) {
            return;
        }

        LOGGER.log(LEVEL, "Compress using " + compressionAlgorithm);
        basicCompressionStream = new BCPGOutputStream(compressedDataGenerator.open(outermostStream));
        outermostStream = basicCompressionStream;
    }

    private void prepareOnePassSignatures() throws IOException, PGPException {
        SigningOptions signingOptions = options.getSigningOptions();
        if (signingOptions == null || signingOptions.getSigningMethods().isEmpty()) {
            // No singing options/methods -> no signing
            return;
        }

        for (SubkeyIdentifier identifier : signingOptions.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = signingOptions.getSigningMethods().get(identifier);

            if (!signingMethod.isDetached()) {
                PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
                signatureGenerator.generateOnePassVersion(false).encode(outermostStream);
            }
        }
    }

    private void prepareLiteralDataProcessing(@Nonnull OpenPgpMetadata.FileInfo fileInfo) throws IOException {
        literalDataGenerator = new PGPLiteralDataGenerator();
        literalDataStream = literalDataGenerator.open(outermostStream,
                fileInfo.getStreamFormat().getCode(),
                fileInfo.getFileName(),
                fileInfo.getModificationDate(),
                new byte[BUFFER_SIZE]);
        outermostStream = literalDataStream;
        resultBuilder.setFileInfo(fileInfo);
    }

    @Override
    public void write(int data) throws IOException {
        outermostStream.write(data);
        SigningOptions signingOptions = options.getSigningOptions();
        if (signingOptions == null || signingOptions.getSigningMethods().isEmpty()) {
            return;
        }

        for (SubkeyIdentifier signingKey : signingOptions.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = signingOptions.getSigningMethods().get(signingKey);
            PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
            byte asByte = (byte) (data & 0xff);
            signatureGenerator.update(asByte);
        }
    }

    @Override
    public void write(@Nonnull byte[] buffer) throws IOException {
        write(buffer, 0, buffer.length);
    }


    @Override
    public void write(@Nonnull byte[] buffer, int off, int len) throws IOException {
        outermostStream.write(buffer, 0, len);
        SigningOptions signingOptions = options.getSigningOptions();
        if (signingOptions == null || signingOptions.getSigningMethods().isEmpty()) {
            return;
        }
        for (SubkeyIdentifier signingKey : signingOptions.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = signingOptions.getSigningMethods().get(signingKey);
            PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
            signatureGenerator.update(buffer, 0, len);
        }
    }

    @Override
    public void flush() throws IOException {
        outermostStream.flush();
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

        try {
            writeSignatures();
        } catch (PGPException e) {
            throw new IOException("Exception while writing signatures.", e);
        }

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

    private void writeSignatures() throws PGPException, IOException {
        SigningOptions signingOptions = options.getSigningOptions();
        if (signingOptions == null || signingOptions.getSigningMethods().isEmpty()) {
            return;
        }
        for (SubkeyIdentifier signingKey : signingOptions.getSigningMethods().keySet()) {
            SigningOptions.SigningMethod signingMethod = signingOptions.getSigningMethods().get(signingKey);
            PGPSignatureGenerator signatureGenerator = signingMethod.getSignatureGenerator();
            PGPSignature signature = signatureGenerator.generate();
            if (signingMethod.isDetached()) {
                resultBuilder.addDetachedSignature(signingKey, signature);
            } else {
                signature.encode(outermostStream);
            }
        }
    }

    public EncryptionResult getResult() {
        if (!closed) {
            throw new IllegalStateException("EncryptionStream must be closed before accessing the Result.");
        }
        return resultBuilder.build();
    }
}
