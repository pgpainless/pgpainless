package org.pgpainless.sop;

import org.pgpainless.sop.commands.ExtractCert;
import org.pgpainless.sop.commands.GenerateKey;
import org.pgpainless.sop.commands.Sign;
import org.pgpainless.sop.commands.Version;
import picocli.CommandLine;

@CommandLine.Command(
        subcommands = {
                Version.class,
                GenerateKey.class,
                ExtractCert.class,
                Sign.class
        }
)
public class PGPainlessCLI implements Runnable {

    public static void main(String[] args) {
        interpret(args);
        // generateKey();
    }

    public static void interpret(String... args) {
        CommandLine.run(new PGPainlessCLI(), args);
    }

    private static void version() {
        CommandLine.run(new PGPainlessCLI(), "version");
    }

    private static void generateKey() {
        interpret("generate-key", "--armor", "Alice Example <alice@wonderland.lit>");
    }

    private static void extractCert() {
        CommandLine.run(new PGPainlessCLI(), "extract-cert");
    }

    private static void sign() {
        interpret("sign", "--armor", "--as=text", "alice.sec");
    }

    @Override
    public void run() {

    }
}
