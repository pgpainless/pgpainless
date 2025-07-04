package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.bcpg.ArmoredInputException;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;

import java.io.EOFException;
import java.io.IOException;

public class ParseCertFuzzTest {

    private final SOP sop = new SOPImpl();

    @FuzzTest(maxDuration = "30s")
    public void parseOpenPGPCert(FuzzedDataProvider data) throws IOException {
        byte[] certEncoding = data.consumeBytes(8192);
        if (certEncoding.length == 0) {
            return;
        }

        try {
            OpenPGPCertificate cert = new OpenPGPKeyReader().parseCertificate(certEncoding);
        }
        catch (ArmoredInputException e) {
            // ignore
        }
        catch (EOFException e) {
            // ignore
        }
        catch (IOException e) {
            // ignore
        }
        catch (UnsupportedPacketVersionException e) {
            // ignore
        }
        catch (ClassCastException e) {

        }
        catch (OutOfMemoryError e) {

        }
    }
}
