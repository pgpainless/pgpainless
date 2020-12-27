package org.pgpainless.sop;

import static org.pgpainless.sop.Print.err_ln;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;

public class SopKeyUtil {

    public static List<PGPSecretKeyRing> loadKeysFromFiles(File... files) throws IOException, PGPException {
        List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
        for (File file : files) {
            try(FileInputStream in = new FileInputStream(file)) {
                secretKeyRings.add(PGPainless.readKeyRing().secretKeyRing(in));
            } catch (PGPException | IOException e) {
                err_ln("Could not load secret key " + file.getName() + ": " + e.getMessage());
                throw e;
            }
        }
        return secretKeyRings;
    }
}
