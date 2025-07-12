// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class SecretKeyPacketFuzzTest {

    @FuzzTest(maxDuration = "30m")
    public void parseSecretKeyPacket(FuzzedDataProvider provider)
    {
        byte[] encoding = provider.consumeBytes(8192);
        if (encoding.length == 0) {
            return;
        }

        ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
        BCPGInputStream pIn = new BCPGInputStream(bIn);
        PGPObjectFactory objFac = new BcPGPObjectFactory(pIn);
        try {
            Object next = objFac.nextObject();
            if (next == null) return;

            PGPSecretKeyRing secKey = (PGPSecretKeyRing) next;
        } catch (IOException e) {
            // ignore
        } catch (UnsupportedPacketVersionException e) {
            // ignore
        } catch (ClassCastException e) {
            // ignore
        }
    }
}
