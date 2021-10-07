// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.KeyIdUtil;

public class SignatureUtilsTest {

    @Test
    public void readSignaturesFromCompressedData() throws PGPException, IOException {
        String compressed = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "owHrKGVhEOZiYGNlSoxcsJtBkVMg3OzZZKnz5jxiiiz+aTG+h46kcR9zinOECZ/o\n" +
                "YmTYsKve/opb3v/o8J0qq1/MFFBhP9jfEq+/avK6qPMrlh70Zfinu96c+cncX9GK\n" +
                "B4ui3fUfbUo8tFrVTIRn7kROq69H77hd6cCw9susVdls1as1gNYunnp5V8Qp+wX3\n" +
                "+jUnwoRB1p4SfPk412lb/cSmShb211fOX07h0JxVH1JXsc/vi2mi5ieG/2Xxb5tk\n" +
                "LE+r7WwruxSaeXLuLsOmXTPZD0/VtvlqO89RYjsA\n" +
                "=yZ18\n" +
                "-----END PGP MESSAGE-----";
        List<PGPSignature> signatures = SignatureUtils.readSignatures(compressed);
        assertEquals(2, signatures.size());
        assertEquals(KeyIdUtil.fromLongKeyId("5736E6931ACF370C"), signatures.get(0).getKeyID());
        assertEquals(KeyIdUtil.fromLongKeyId("F49AAA6B067BAB28"), signatures.get(1).getKeyID());
    }

    @Test
    public void noIssuerResultsInKeyId0() throws PGPException, IOException {
        String sig = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsEaBAABCABOBYJhVBVcRxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ+goUZDURlALH597rQCp41yYHOF90OfPRrp6TSZAA/nQAAAeOQwAni7j\n" +
                "R4YEXpcDfqwjOPIvq5i7VWBR5EdESvR1fJHD99y4TyllezSpQcmZSGrkIcFRgTxR\n" +
                "CwJ6oOsY4QILFF5N330Bs7HQfTbdgpx29ELo+8PuizRvhRVlQack/GPoRON/QQDz\n" +
                "EBjZwiiPHgyw3CeQahHqSPgUT5JvW5yOOs31AhDlgen0qRHKtRwaI+5M5Y9nHR6z\n" +
                "H2o5xapE4Vz647sPkl269Sd4kl/qkInoyKf1x1U6bu6g9Onr1fafM1HLiGkJl0Sk\n" +
                "YNHCHdnBbyZBJt3ijCokOAGe7DIHvz5rv9iO/WDdC5Tw9XJlrFTI4xAv0EXJCSZm\n" +
                "9eVJbaOEmnjqwaZNf4tS+j6+Blp/1p0YMd/10Fh6cmLYyM2mDBB60pE/Y3ARS1lP\n" +
                "fta43BXTAWu6h+ZT2gncbBv+yAxmMEMY2iBk11dCLrSFWGEcitrOigCLMrPdCKCl\n" +
                "7zv9ar9WsNOibOEaso+MF7oAw+97o1nRXPHg/5FzcmosqKU3VJZU8QZfETO7\n" +
                "=YWPw\n" +
                "-----END PGP SIGNATURE-----";
        PGPSignature signature = SignatureUtils.readSignatures(sig).get(0);
        assertEquals(0, SignatureUtils.determineIssuerKeyId(signature));
    }

    @Test
    public void skipInvalidSignatures() throws PGPException, IOException {
        // Sig version 23 (invalid), sig version 4
        String sigs = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7FwABCgBvBYJhVBVECRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfYpOWFSlKZpeZQTVMyX5UaWW+12r4Xb0EAFS4gOWJ/\n" +
                "mhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABpyQwAorVkBMS2DTb5rYFPjWjoIo1A\n" +
                "3SiYkgPzddqc8ZvTu3zlEXpoGzKQLrXW3AGCuXCeEst+kPV6j33zZiPFSdcn0Ddg\n" +
                "QUWlxhmsVJ/ePujwfVyPLJISE/g1486qMERSnOKKyL7u62uwCggRzZMYKOC12PFO\n" +
                "+9OsISkPs+BqsV7jd6L2NJCBZ0VFCP2kE4vMty0VltIa3nfr1PgWPH3ekBPt3a0p\n" +
                "OF/aSckV0gy4t7JqT9nxU5oWwxef1TQuQ8yh96gBSFUcS58ov+tBuMIjphpKexxU\n" +
                "HlOTDVRG8+qUiScGFrc1aavepd9x60aHLBSwyGt4/ZhPvRp3fljyGqSapSUmCeFJ\n" +
                "FN+p7Ne35GO/lrr6Aao3HH1xVGF4+Jn7N8CgN/dsKWa+gSrnKZbYo0Sa7hx6yRtm\n" +
                "a45VSoRmjEjP+cL+lvDBTqvv3anufZ5OCIzt2sUFJfWF6bOPjc+1X294qYNpVX6j\n" +
                "xFWiAQt5XvispaNnuHE5tnlI7pLJ66zCU/Kl4WgywsE7BAABCgBvBYJhVBVECRD7\n" +
                "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfY\n" +
                "pOWFSlKZpeZQTVMyX5UaWW+12r4Xb0EAFS4gOWJ/mhYhBNGmbhojsYLJmA94jPv8\n" +
                "yCoBXnMwAABpyQwAorVkBMS2DTb5rYFPjWjoIo1A3SiYkgPzddqc8ZvTu3zlEXpo\n" +
                "GzKQLrXW3AGCuXCeEst+kPV6j33zZiPFSdcn0DdgQUWlxhmsVJ/ePujwfVyPLJIS\n" +
                "E/g1486qMERSnOKKyL7u62uwCggRzZMYKOC12PFO+9OsISkPs+BqsV7jd6L2NJCB\n" +
                "Z0VFCP2kE4vMty0VltIa3nfr1PgWPH3ekBPt3a0pOF/aSckV0gy4t7JqT9nxU5oW\n" +
                "wxef1TQuQ8yh96gBSFUcS58ov+tBuMIjphpKexxUHlOTDVRG8+qUiScGFrc1aave\n" +
                "pd9x60aHLBSwyGt4/ZhPvRp3fljyGqSapSUmCeFJFN+p7Ne35GO/lrr6Aao3HH1x\n" +
                "VGF4+Jn7N8CgN/dsKWa+gSrnKZbYo0Sa7hx6yRtma45VSoRmjEjP+cL+lvDBTqvv\n" +
                "3anufZ5OCIzt2sUFJfWF6bOPjc+1X294qYNpVX6jxFWiAQt5XvispaNnuHE5tnlI\n" +
                "7pLJ66zCU/Kl4Wgy\n" +
                "=fvS+\n" +
                "-----END PGP SIGNATURE-----\n";
        List<PGPSignature> signatures = SignatureUtils.readSignatures(sigs);
        assertEquals(1, signatures.size()); // first sig gets skipped
    }
}
