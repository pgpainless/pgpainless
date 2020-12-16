package org.pgpainless.sop.commands;

import picocli.CommandLine;

@CommandLine.Command(name = "version", description = "Display version information about the tool")
public class Version implements Runnable {

    @Override
    public void run() {
        System.out.println("PGPainless CLI version 0.0.1");
    }
}
