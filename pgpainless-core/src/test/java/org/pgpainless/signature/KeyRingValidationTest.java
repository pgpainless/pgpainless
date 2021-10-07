// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.key.KeyRingValidator;
import org.pgpainless.policy.Policy;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.DateUtil;

public class KeyRingValidationTest {

    private static Policy.HashAlgorithmPolicy defaultSignatureHashAlgorithmPolicy;

    @BeforeAll
    public static void setCustomPolicy() {
        Policy policy = PGPainless.getPolicy();
        defaultSignatureHashAlgorithmPolicy = policy.getSignatureHashAlgorithmPolicy();

        policy.setSignatureHashAlgorithmPolicy(new Policy.HashAlgorithmPolicy(HashAlgorithm.SHA256, Collections.singletonList(HashAlgorithm.SHA256)));
    }

    @AfterAll
    public static void resetCustomPolicy() {
        PGPainless.getPolicy().setSignatureHashAlgorithmPolicy(defaultSignatureHashAlgorithmPolicy);
    }

    @Test
    public void testSignatureValidationOnPrimaryKey() throws IOException, PGPException {
        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwIcEIAEKABoFglwqrYAT\n" +
                "HQFLZXkgaXMgc3VwZXJzZWRlZAAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhP\n" +
                "rWLcA4+76+wH/1NmN/Qma5FTxmSWEcfH2ynKhwejKp8p8O7+y/uq1FlUwRzChzeX\n" +
                "kd9w099uODMasxGaNSJU1mh5N+1oulyHrSyWFRWqDnQUnDx3IiPapK/j85udkJdo\n" +
                "WfdTcxaS2C9Yo4S77cPwkbFLmEQ2Ovs5zjj0Q+mfoZNM+KJcsnOoJ+eeOE2GNA3x\n" +
                "5TWvw0QXBfyW74MZHc0UE82ixcG6g4KbrI6W544EixY5vu3IxVsxiL66zy27A8ha\n" +
                "EDdBWS8kc8UQ2cRveuqZwRsWcrh/2iHHShY/5zBOdQ1PL++ubwkteNSU9SsXjjDM\n" +
                "oWm1RGy7/bagPPtqBnRMQ20vvW+3oBYxyd7CwHwEHwEKAA8Fgl4L4QACFQoCmwMC\n" +
                "HgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q60dg60qh\n" +
                "A2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wHeTsjSd/D\n" +
                "RI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9WHurxXeW\n" +
                "XOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI3cRKObCF\n" +
                "JaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcysQ/USxEkL\n" +
                "hIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fCcs55+n6k\n" +
                "C9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdItX+pWP+o\n" +
                "3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nws5fc3JH4\n" +
                "R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYWY7gP7Z4C\n" +
                "j0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2WXKgVhy7\n" +
                "/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSSVt0nhzWu\n" +
                "XJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80SanVsaWV0\n" +
                "QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE8tFQpP6Y\n" +
                "kl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPjtaTvGfo1\n" +
                "SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9HhbgTrUNvW1e\n" +
                "g2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzCrl3xWTxj\n" +
                "T5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39ZmWWQKJZ\n" +
                "0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN3DU4XtF+\n" +
                "oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuAAQgAykb8\n" +
                "tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVOR/hcOUlO\n" +
                "GH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pletzCR4x3\n" +
                "STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5ShFYexgS\n" +
                "rKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vmsSVTWyj0\n" +
                "AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4wyRsxj7S\n" +
                "u+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsCAVcJEGhPrWLcA4+7\n" +
                "wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK81MtR1mh1WVLJRgXW\n" +
                "4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITskMrWCDaoDhD2teAj\n" +
                "mWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RKSES1KywBhfONJbPw\n" +
                "1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xpwBYNlhasXHjYMr4H\n" +
                "eIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1bA35FNnl637M8iCN\n" +
                "rXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekVOWhPrWLcA4+7FLwI\n" +
                "AK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4OydkEDvmNVVhlUcfg\n" +
                "Of2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB9CuJFpILn9LZ1Ei6\n" +
                "JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg709YVgm2OXsNWgktl9\n" +
                "fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+dTJsYGhnc96EtT8E\n" +
                "fSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05AmoV7wlgzUAMsW7MV2\n" +
                "NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIBVwkQaE+tYtwDj7vA\n" +
                "dKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9qU6TuRFKcjSjoSE6\n" +
                "ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ3DUyjxhAyRDpI2Cr\n" +
                "ahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUKcq2zNA6ixO2+fQQh\n" +
                "mbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNlNik9ASPWyn0ZA0rj\n" +
                "J1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+OcPEz0GgZfq9K40di3\n" +
                "r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpRMDibCQh+7fbqyQEM\n" +
                "/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tOtggA\n" +
                "hgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmbnJymzo77+OT+SScn\n" +
                "DTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuXOjbJ1N8I08pB2nih\n" +
                "t5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/sZocNmaTv0/F8K3Ti\n" +
                "rSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg3whc0XD+5J9RsHoL\n" +
                "33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0Y87zSryajDMFXQS0\n" +
                "exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=qQpG\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);

        Date validationDate = DateUtil.parseUTCDate("2019-05-01 00:00:00 UTC");
        Policy policy = PGPainless.getPolicy();
        PGPPublicKeyRing evaluated = KeyRingValidator.validate(publicKeys, policy, validationDate);

        // CHECKSTYLE:OFF
        System.out.println(ArmorUtils.toAsciiArmoredString(evaluated));
        // CHECKSTYLE:ON


    }
}
