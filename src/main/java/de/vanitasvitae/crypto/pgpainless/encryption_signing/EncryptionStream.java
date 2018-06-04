package de.vanitasvitae.crypto.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class EncryptionStream extends OutputStream {

    private final OutputStream outputStream;
    private final Set<PGPPublicKey> encryptionKeys;
    private final Set<PGPSecretKey> signingKeys;
    private final SymmetricKeyAlgorithm symmetricKeyAlgorithm;
    private final HashAlgorithm hashAlgorithm;
    private final CompressionAlgorithm compressionAlgorithm;
    private final boolean asciiArmor;

    private EncryptionStream(OutputStream outputStream,
                            Set<PGPPublicKey> encryptionKeys,
                            Set<PGPSecretKey> signingKeys,
                            SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                            HashAlgorithm hashAlgorithm,
                            CompressionAlgorithm compressionAlgorithm,
                            boolean asciiArmor) {
        this.outputStream = outputStream;
        this.encryptionKeys = encryptionKeys;
        this.signingKeys = signingKeys;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.compressionAlgorithm = compressionAlgorithm;
        this.asciiArmor = asciiArmor;
    }

    public static EncryptionStream create(OutputStream outputStream,
                                          Set<PGPPublicKey> encryptionKeys,
                                          Set<PGPSecretKey> signingKeys,
                                          SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                          HashAlgorithm hashAlgorithm,
                                          CompressionAlgorithm compressionAlgorithm,
                                          boolean asciiArmor) {

        requireNonNull(outputStream, "outputStream");
        requireNonNull(encryptionKeys, "encryptionKeys");
        requireNonNull(signingKeys, "signingKeys");
        requireNonNull(symmetricKeyAlgorithm, "symmetricKeyAlgorithm");
        requireNonNull(hashAlgorithm, "hashAlgorithm");
        requireNonNull(compressionAlgorithm, "compressionAlgorithm");



        return new EncryptionStream(outputStream,
                encryptionKeys,
                signingKeys,
                symmetricKeyAlgorithm,
                hashAlgorithm,
                compressionAlgorithm,
                asciiArmor);
    }

    @Override
    public void write(int i) throws IOException {

    }

    private static void requireNonNull(Object o, String name) {
        if (o == null) {
            throw new IllegalArgumentException("Argument '" + name + "' MUST NOT be null.");
        }
    }
}
