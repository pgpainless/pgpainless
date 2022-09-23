package org.pgpainless.decryption_verification;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.OpenPgpPacket;
import org.pgpainless.util.ArmoredInputStreamFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class TeeBCPGInputStreamTest {

    private static final String INBAND_SIGNED = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "owGbwMvMyCUWdXSHvVTUtXbG0yJJDCDgkZqTk6+jEJ5flJOiyNVRysIoxsXAxsqU\n" +
            "GDiVjUGRUwCmQUyRRWnOn9Z/PIseF3Yz6cCEL05nZDj1OClo75WVTjNmJPemW6qV\n" +
            "6ki//1K1++2s0qTP+0N11O4z/BVLDDdxnmQryS+5VXjBX7/0Hxnm/eqeX6Zum35r\n" +
            "M8e7ufwA\n" +
            "=RDiy\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void test() throws IOException, PGPException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(out);

        ByteArrayInputStream bytesIn = new ByteArrayInputStream(INBAND_SIGNED.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(bytesIn);
        BCPGInputStream bcpgIn = new BCPGInputStream(armorIn);
        TeeBCPGInputStream teeIn = new TeeBCPGInputStream(bcpgIn, armorOut);

        ByteArrayOutputStream nestedOut = new ByteArrayOutputStream();
        ArmoredOutputStream nestedArmorOut = new ArmoredOutputStream(nestedOut);

        PGPCompressedData compressedData = new PGPCompressedData(teeIn);
        InputStream nestedStream = compressedData.getDataStream();
        BCPGInputStream nestedBcpgIn = new BCPGInputStream(nestedStream);
        TeeBCPGInputStream nestedTeeIn = new TeeBCPGInputStream(nestedBcpgIn, nestedArmorOut);

        int tag;
        while ((tag = nestedTeeIn.nextPacketTag()) != -1) {
            System.out.println(OpenPgpPacket.requireFromTag(tag));
            Packet packet = nestedTeeIn.readPacket();
        }

        nestedArmorOut.close();
        System.out.println(nestedOut);
    }
}
