package org.pgpainless.sop.commands;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionBuilderInterface;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.sop.Print;
import picocli.CommandLine;

@CommandLine.Command(name = "sign")
public class Sign implements Runnable {

    public enum Type {
        binary,
        text
    }

    @CommandLine.Option(names = {"--armor"}, description = "ASCII Armor the output")
    boolean armor = false;

    @CommandLine.Option(names = {"--no-armor"})
    boolean noArmor = false;

    @CommandLine.Option(names = "--as", description = "Defaults to 'binary'. If '--as=text' and the input data is not valid UTF-8, sign fails with return code 53.")
    Type type;

    @CommandLine.Parameters
    File secretKeyFile;

    @Override
    public void run() {
        PGPSecretKeyRing secretKeys;
        try {
            secretKeys = PGPainless.readKeyRing().secretKeyRing(new FileInputStream(secretKeyFile));
        } catch (IOException | PGPException e) {
            System.err.println("Error reading secret key ring.");
            System.err.println(e.getMessage());

            System.exit(1);
            return;
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            EncryptionBuilderInterface.DocumentType documentType = PGPainless.encryptAndOrSign()
                    .onOutputStream(out)
                    .doNotEncrypt()
                    .createDetachedSignature()
                    .signWith(new UnprotectedKeysProtector(), secretKeys);

            EncryptionBuilderInterface.Armor armor = type == Type.text ? documentType.signCanonicalText() : documentType.signBinaryDocument();
            EncryptionStream encryptionStream = noArmor ? armor.noArmor() : armor.asciiArmor();

            Streams.pipeAll(System.in, encryptionStream);
            encryptionStream.close();

            PGPSignature signature = encryptionStream.getResult().getSignatures().iterator().next();

            System.out.println(Print.toString(signature.getEncoded(), !noArmor));
        } catch (PGPException | IOException e) {
            System.err.println("Error signing data.");
            System.err.println(e.getMessage());

            System.exit(1);
        }
    }
}
