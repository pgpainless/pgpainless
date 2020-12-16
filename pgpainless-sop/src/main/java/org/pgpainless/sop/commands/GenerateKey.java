package org.pgpainless.sop.commands;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.Print;
import org.pgpainless.util.ArmorUtils;
import picocli.CommandLine;

@CommandLine.Command(name = "generate-key")
public class GenerateKey implements Runnable {

    @CommandLine.Option(names = {"--armor"}, description = "ASCII Armor the output")
    boolean armor = false;

    @CommandLine.Option(names = {"--no-armor"})
    boolean noArmor = false;

    @CommandLine.Parameters
    String userId;

    @Override
    public void run() {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing(userId);

            System.out.println(Print.toString(secretKeys.getEncoded(), !noArmor));

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | PGPException | IOException e) {
            System.err.println("Error creating OpenPGP key:");
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
