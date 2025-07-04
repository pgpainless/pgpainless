package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.bouncycastle.util.Arrays;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AsciiArmorFuzzTest {

    private final SOP sop = new SOPImpl();

    @FuzzTest()
    public void armorAndDearmorData(FuzzedDataProvider data) throws IOException {
        byte[] bytes = data.consumeBytes(1024);

        byte[] armored = sop.armor().data(bytes).getBytes();
        if (Arrays.areEqual(bytes, armored)) {
            // armoring already armored data is idempotent
            return;
        }

        byte[] dearmored = sop.dearmor().data(armored).getBytes();
        assertArrayEquals(bytes, dearmored, new String(armored));
    }
}
