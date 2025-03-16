// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.policy.Policy;
import sop.ByteArrayAndResult;
import sop.Verification;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class VerifyLegacySignatureTest {

    @Test
    public void verifyLegacySignature() throws IOException {
        // Key generated in 2012 using SHA1 for self sigs
        String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 21FA 6E60 D6C9 B7D1 0EAC  56A2 984B 91CF D303 214C\n" +
                "Comment: Legacy <legacy@example.com>\n" +
                "\n" +
                "lQVYBFDUVsABDADg6AuFsM0JckT7spS/1KNdobaZ1vrOFhGdyXbJ1jUkbMwi+f5o\n" +
                "UtQsfeFQRBHeQFfmtt4mo6lE6cAsQFJPFat/ReNxCwCqHi5QbennpbueHJ5N2KVj\n" +
                "YrIz6eeTsVKs16gS17zLOMkeBt0TK8+Vu7HHfqLqQ1jNNGujwPydUbO8M431XKeW\n" +
                "WhM9ziV9m/20nHYJGIM+aN9AicxtR+khFsNjpRlCMg+8kKUelP2FDWv/5QZwnSXc\n" +
                "nMFaCJiH1hx56027AB8PZrUW+ShRhqb0P3EhOt+Gs3IW39rGjc9iQVEWl7745BTZ\n" +
                "xEZ4FO84DQQtdKBp510VN8LfiZkO7K9JKOo+vqL4IvSBCJNRVvxDxInShHfVyht7\n" +
                "jJJvEC0mxv1Oi8rZ/g9iNd6/Ijthi3svNd3DwNFyMzhrbggynEyWr8nu17Zz0c6C\n" +
                "KT7XtFZWOUmio8G14KH6dFRCt7TGRw7mz059ViICMN56Ka5LJaQgGRbT+omY2CQJ\n" +
                "q5eSkZMXLndmjtUAEQEAAQAL+QFsyzhLl/oLPs0+63JrTaXPY9s5EpNEkHYTgN29\n" +
                "HTUELKdWFBaa7M9sBbCJmiODdEB0mfT+yGW9R6wPCXiaEj8ysMt0QvVzG03Qr6pX\n" +
                "kWCmHSuW5ZQHytJjDJMA0T+3K0fQWWFPC/bmX12+1Flw4qI9g6oigub1aF4eJFdV\n" +
                "XVq7vhadY9aSIiGtJnX+PqiRIIwPeRDfMjsvwA6H/1dwftltRnbLVr0vnUutRnPv\n" +
                "ZGbiOim35bWubLW55Ehycb4T4KyW70Xq0Lljr04/33d7S/SUNHXM/ci2kFDEkJb8\n" +
                "N+rssxaVjgPsn9+5wQFDEcrewdMLgaRHSrEf46GvcYMbM8lfnzrDyhYc5+vc24b5\n" +
                "85WCVYaYKFrJGEa1vHAMmDwXqDNETtDtaYXZpNsUqvjlG+lU4/p0zeqGfyIDLnzK\n" +
                "R5zAmWQkd4aSrgN4F6/7xQ1npnvBq/eZiHJx4sBsPMS10TFPPi3A9jEAiu0eljTq\n" +
                "E7eXqDObHD8xSjQ3gm9fBclTUQYA4vVChPT9SgJo2aY5ug+2nLWfv4hgK2LTRNkt\n" +
                "exEelaU3vrl83a/HEljg3DZ63P6odRIv0HGRl4YSOEC5CANDcDqjz34p7T6suRU5\n" +
                "GzrZHey33joLj9oAGF+2HefmHpvWc8ZzFaS14XiO4m9TMMLZwSokNyhccHl7FSYZ\n" +
                "XqxzXD2JnaM+m3XMGRVnASQ2gtmsv8dpXuto+gF/9W1b8kyPp1sjtgup2O4PjiQg\n" +
                "1uQMpx6H3OSC8tCH3f9/MvlVTpgtBgD9r5PnN5h6fQd6MQl7UEdTU3jIOcXrr1xh\n" +
                "0rQkTQx1WJ29f/tr/sGPb3HgPcpk+x6xctRVpW6yf6OLBP02CnJllBYE73tqIxxa\n" +
                "qK+3kDAqIa9n/Ds8SZTH/45JXDFLay5g7kFMpv6dxUUMtdJ8INmcChVPxKeUB5DZ\n" +
                "iGMzmCTsR0RxvEIc3ofht7mrMhH361xUZGbIMP6ykZZNlE4FmOW4zBATa8o4V3gl\n" +
                "mdbIYopEGPwAuj1gIy0G7fLL0cayEkkF/RI7uep4d2QY87mC+fswbiPWM3mp6/7i\n" +
                "e2JLmA2bdDju7SL6X4DMgV8RQakOlQf17JEGA4HrKi3odugiBjdXWv6ZmfcIIPgq\n" +
                "ns2Us6wCcr4uqCxEvYj2fUd/q03ui5aglLTqSSuNtnB9yww0EYrj9qjHFIi/ByrF\n" +
                "L6DVBrMDJ0BwHY5LkY1OWot4GyjLE43Uqu0ObZhFSMttGQkRxdae0R9+4NPR7Dlw\n" +
                "B8+zwytxGRs1NgTy7O+KRl9e3K05bgUXVNsJtBtMZWdhY3kgPGxlZ2FjeUBleGFt\n" +
                "cGxlLmNvbT6JAdAEEwECAEQJEJhLkc/TAyFMFiEEIfpuYNbJt9EOrFaimEuRz9MD\n" +
                "IUwFglDUVsACngECmwMFFgIDAQAECwkIBwIVAgWJH6AIMQKZAQAAWU0L/jUvlxt0\n" +
                "TLLFTcT1tQWvy1MBLJcdiXuoN0/w1Rcz54iSCgWeuNZ5BD6qwCMORmVG1fMuvtCt\n" +
                "Lq4NZizE63QfeFE8q22vrNDoZ5pAnjC7KlMMjq1ykQHN7cqH1FgxrS3PrBo1k8/s\n" +
                "0P6863Vlso02YYbWluJt4HbnX0vEap4/z05RLBCQyZyiaon5zad5rNd0z1nXfMC8\n" +
                "EPRK9MsjBX5/5zhx6RPwCrAlrk5dKZ3Nks6bquTCme8sayBgBHX0Tjeum+3sfwiE\n" +
                "Jn2xTYJU6cB7fWYREi9E9z7YrmpVCjDkh8U7p0MLC3dmIYUT3EDL5F0jxTReoX+B\n" +
                "7f8HrKUIOyvLlAJs4oxYG/g9QHzVFSAbekwf3Jnwm4Czd6qPx62gI6na11ku64Ua\n" +
                "RezZ3NkTInSXi1+Bi7mT4qVcV6Z6vl5YXe8T/Zihcv5/Wp4bNEJ2dHJlhwVAn8Ax\n" +
                "Ykl8S2ZVfQ5hN8gWLRW40wnCrbuNUdWI/el9D1arc8AQclXfF8/4kULTq50FWARQ\n" +
                "1FbAAQwAv/eK+LYwdkUoGfATB6wcmqaJFrjFIaKYbM1VEWckb4FYc0T1yc9MEq65\n" +
                "gz1/PUPt+XwQCa/gP5iCcVuze91ksJVkoeOjy/CQgMD1D1s0IVikVMvOKqdnVa4k\n" +
                "SxkLkOvVdzZ5QebDbE5QqfTupyr/SgWarm7TYb4HVFNG5xXVh8+uFMpLe897E+/K\n" +
                "mSQMZZ8vdKVvnEm+EOlm0ZzRml4kM8k1LyVxJdoLUJ0t5Ac7B1k/Xq0Fz1Pl3Yjr\n" +
                "xahxvz68gTph+uL0IlnxKIt+lI2YKTaZ/QZ6POzif0UHLH4akEoTLjzlzkgNYdiI\n" +
                "O3ZekqHViYtlX0brc7TYo3iip1LIvv3NMI7QskA2v9V1NWcf/cPBt0uwJ2wMDDDy\n" +
                "bckrrwwsfNn6qFxY3xFo1aexzgpG2C9ZVpIDLMd3F6SUoqrrmAHJLoP0dSYBVujO\n" +
                "EAJdPqvLC45KJFgXu6IrBqFrx+WTACJCvgoF8XLLhEba99CwmS8Rc2luS+G3iB8l\n" +
                "YQlj5QWXABEBAAEAC/wMe00lhe/f7ZGbIVYun4ahZfnWTyxyI9JPvYh62ZjJSNqD\n" +
                "B2IIo/PitLDXObGcpPgQl3wR3sYKT7sOuwZ2ihsFgd38yk8lVktVZwM7SZQGi9VT\n" +
                "gu59+eVPV6oaDLmimJ+7YQCNXZj2ewXmDXwe+Aq7ucjCIrtklY7m14Tt4MH1H9z5\n" +
                "X3xJw2A4GAiCRvfClV3oJbTJSRPH1Ouch9r3c7uPqm6zPBBmHg4Yr1k2hGNwKa6X\n" +
                "IOtJyb8ebzKogJ7n7zo4Cpst01PkdLPnXK3fTEBYjuBQa5F2sSvT89uK3seN3J7W\n" +
                "OP05lCcg1k9e4bnD9uGlba0fhsgUhqTEg3za6MNcVezPqRXGXlkWH5gjxbVQHu8B\n" +
                "Y8Ix9YvWhCwIA25bSE51bTq2vQuCTaRG5fXVWD8qZ043APcB99c9zW9OvmiJzH47\n" +
                "zYk+rB+lByK8/KiaXUqcKjyUniXc9LKda71xb4MwoBuBF9RdCsQvHwFRibdpMd0t\n" +
                "a9O7RoTFKPxhUewySoEGANTBWhstEUlsytFMSeNmCmpNR2/mKbuE+n78+zaPCmLF\n" +
                "TsLWxil+y3FrJCvffn9k5shtxLADtEvKJKWl/vjXxh9DXzFvMgRPsrETzAkg0zwr\n" +
                "+5P8d26x4xcnQaE59RQIhyiJPsT4fXqld+kaKDng0vYkVRGHSIC//NPMPA2KaTdC\n" +
                "4EQvEx702dF3/+tIDwXO/kjk6taEEOv0W5nj0aHm+JtEw+X0ja1VvUcDx50Ttwpc\n" +
                "LzojtWjFpBNFHLGZyWac4QYA5vx6WsovX9j3YXkYDHbN+r8rCfL/16+z+qEJ/pbw\n" +
                "2eevICtB4KLcqXlep4rSLhDJlYphxZfHhsVahwX1ga+fGDB/AuDozJhtfQp7evwN\n" +
                "NH5IIAT3o56iBUIO2CywWcdkY+HMo787MbITfvVOdOrGE8hRcCFdkZepaSwfbTRz\n" +
                "LZH+jKAU6xOgInuoPVLOOIIlLaTVb6TTRV9BXyRUdele0DqbZIMCwE8P53kFuGuM\n" +
                "sRZQ1RNha8H7WU2T2m7QxDl3Bf4+KYQ5AfFPkGZKMQcIJy4CR7hSP9gk3/4B06RM\n" +
                "DH3c4rmd50CPpQ5TTA0cGCthOnYVewUgJaxQjKAToX8xCQYFRO59YOc8PMVZ/xgf\n" +
                "kGrEkX4tlwECbjoWx2kWT4uZvYmnUzfDdXXr8E+9h2ziEKobF0/b9HQB5BKKLycr\n" +
                "KzoTKbV4En1602VltRInAfnjpmQ7VSYV/JyoHJ824d/7O+fLLZkmyibLiSMWPwYu\n" +
                "z9rt26lC3cT/HSMrG3L0jjdWH7bYaIkBsAQYAQIAGgWCUNRWwAKeAQKbDAUWAgMB\n" +
                "AAQLCQgHAhUCAAoJEJhLkc/TAyFMEn4MAKI6RC+VUJr+p2bMf5Pbfml/iy5QsRBG\n" +
                "J1iTyPzu8yJUzHs60y6YckGrIKSFE5x6a6utz/CdtpIlb9e/FJvl82zjxJkFjhre\n" +
                "fhHjcu6iIvLCCer6v1XtL4frx6Qoi6TGmlKXWvaLTuRINQFomLwScoHRW1QSQHTE\n" +
                "BNUmIo89nRU5PQ8LJBGZWzdkVqVmdbK8ek5ycuolwLUQizbeGIhJo/9IIC2i2RCJ\n" +
                "hMVsmbjHB1zdVbwPZuwtCH7ROr4xTLp9Gwq1XcIRYY5am/SyBLgkwKSyrXQs6Zsr\n" +
                "2qRd2+ccBF0UYFxvH9JOKmBS6QGwtnAYRqbeeCj8Lx3mgAIv15kGeKd72ezFi0ZT\n" +
                "smO3dpb6pSD44BSsdvjZdHENCxYIbBsroDZrZGShygluOCrFjG//PSSbrNE+Bz70\n" +
                "imnM2QH/XaS6rpbNPGfrn0Vw5M/ZFT/9PWrEg4ZdCI32ei5uyjYwL7aPAPS3MqkB\n" +
                "SV9g8CiU0cX7hiBYYpktcDVU3uRCR4Fkvw==\n" +
                "=n8qw\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        // Sig generated in 2012 using SHA1
        String oldSig = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "owEB2gEl/pANAwACAZhLkc/TAyFMAcsTYgAAAAAASGVsbG8sIFdvcmxkIYkBswQA\n" +
                "AQIAJwkQmEuRz9MDIUwWIQQh+m5g1sm30Q6sVqKYS5HP0wMhTAWCUNRWwAAALxEL\n" +
                "/2uhYsTLM8nUnYm2GJB6pkapX1kbQrqfAhK46IjxcPpRdl6CW4cFrG6iFegx4YLE\n" +
                "fu44VKG+XGy/RTZXIEJubi9zVyOGGJM9Bwwdcp/eekO16/kJ7BsbkaO+5AG/fNeg\n" +
                "bL5C8D2m6jV1seAt/+tRyM9jLkRi9odq8BsGA6ZcthAxh3MUoo1yw3QwwEcFFHg/\n" +
                "gBw4ZtL8KIQN1PKDz3sSV4GXPQAiz+/uADZ2lL6mbDEK/gXAK1KevIO3U8ZU9B6l\n" +
                "cOF9fJww31SCqFGDq50Lzwz7eySJB1TZ0IoehGDXoQ8JF88uTVfACkBATE0Zx7zg\n" +
                "TAYIgPSjWY4TEDZ9YjdxJ0hKTMncxVfZPB+J/mYCpVADYSEhLbUJ1ntjc0s35xJD\n" +
                "udLSwUWuboedVdEcaqnfgHoaaV+nKk+6F9y8NO56RK3Bfx5FmKmNZHbhfXO/qRt9\n" +
                "H43UktMUD6xWxxJv7mutThOp2aizBeboa5YSJ1mxtkPW0/lyK1jr438ETHUnCeu6\n" +
                "Vw==\n" +
                "=TtKx\n" +
                "-----END PGP MESSAGE-----";

        SOPImpl sop = new SOPImpl();
        byte[] cert = sop.extractCert().key(KEY.getBytes(StandardCharsets.UTF_8))
                        .getBytes();
        ByteArrayAndResult<List<Verification>> result = sop.inlineVerify()
                .cert(cert)
                .data(oldSig.getBytes(StandardCharsets.UTF_8))
                .toByteArrayAndResult();

        assertFalse(result.getResult().isEmpty());

        // Adjust data signature hash policy to accept new SHA-1 sigs
        Policy policy = PGPainless.getPolicy();
        Policy adjusted = policy.copy()
                        .withDataSignatureHashAlgorithmPolicy(
                                Policy.HashAlgorithmPolicy.static2022RevocationSignatureHashAlgorithmPolicy()
                        ).build();
        PGPainless.getInstance().setAlgorithmPolicy(adjusted);

        // Sig generated in 2024 using SHA1
        String newSig = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "owEB2gEl/pANAwACAZhLkc/TAyFMAcsTYgAAAAAASGVsbG8sIFdvcmxkIYkBswQA\n" +
                "AQIAJwWCZw5i2AkQmEuRz9MDIUwWIQQh+m5g1sm30Q6sVqKYS5HP0wMhTAAAhVML\n" +
                "+QGH+O2fEJoAY8ZxKz/mosg4it9IeSzMhBvDgZJE8Jc+VGk7EuXL0M8pfHL+Jgmv\n" +
                "FMzF3chzzLS7QA4K6hbxO31/M8TNSU12geuzQiBV7Kb1hjpvIObBgEqYsX50ZV8r\n" +
                "5DHcr7huABUOH6tCKmCA2OxOvr1QV8X39h856bz3WqqP9HW8kZ6H1Z6d7XWlRMtW\n" +
                "mAnSevvOJbb0Z3D97obYqytSLzi2Jyv+w2R9kYzMQff2Rl6Cv4F7zsRrF9JRC0m6\n" +
                "X/s+VSNuT2yG0/4F5y8vrxvNkfd8YfM8DM6irJV4yJyVuwIoZnM913XCA4F7Uo4t\n" +
                "Z8ER17SY4WOYvdja/7qPcOUjX5n1dDU0W7q2muqnZXREw2JXTULiDl0MET3K4kFu\n" +
                "a6FyyMGGQwFpAnZ4gDZKzw06abd95AgHx4QlkD89J7MnUBBV+AGHNAQlCPPEVPQq\n" +
                "dWTInYndt4GKCUxVkJeHD6ZPLdxEEvICmEap4FQzhqM8U7weoEsSinoVoc4JmSY9\n" +
                "dQ==\n" +
                "=XrzP\n" +
                "-----END PGP MESSAGE-----";
        result = sop.inlineVerify()
                .cert(cert)
                .data(newSig.getBytes(StandardCharsets.UTF_8))
                .toByteArrayAndResult();

        assertFalse(result.getResult().isEmpty());

        // Reset old policy
        PGPainless.getInstance().setAlgorithmPolicy(policy);
    }
}
