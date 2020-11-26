package org.pgpainless.sop.commands;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.sop.Print;
import org.pgpainless.util.BCUtil;
import picocli.CommandLine;

@CommandLine.Command(name = "extract-cert")
public class ExtractCert implements Runnable {

    @CommandLine.Option(names = {"--armor"}, description = "ASCII Armor the output")
    boolean armor = false;

    @CommandLine.Option(names = {"--no-armor"})
    boolean noArmor = false;

    @Override
    public void run() {
        try {
            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(System.in);
            PGPPublicKeyRing publicKeys = BCUtil.publicKeyRingFromSecretKeyRing(secretKeys);

            System.out.println(Print.toString(publicKeys.getEncoded(), !noArmor));
        } catch (IOException | PGPException e) {
            System.err.println("Error extracting certificate from keys;");
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
