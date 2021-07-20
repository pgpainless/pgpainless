package sop.cli.picocli.commands;

import picocli.CommandLine;
import sop.exception.SOPGPException;

@CommandLine.Command(name = "detach-inband-signature-and-message",
        description = "Split a clearsigned message",
        exitCodeOnInvalidInput = SOPGPException.UnsupportedOption.EXIT_CODE)
public class DetachInbandSignatureAndMessageCmd implements Runnable {
    
}
