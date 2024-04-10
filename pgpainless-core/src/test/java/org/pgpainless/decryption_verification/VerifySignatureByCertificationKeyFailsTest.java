// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class VerifySignatureByCertificationKeyFailsTest {

    // Key with non-signing primary key and dedicated signing subkey
    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: ACFC 7FFA 02BE C1E8 5002  2D35 AFE4 67B2 9A41 A0CE\n" +
            "Comment: Complex RSA <test@test.test>\n" +
            "\n" +
            "lQcYBGYQBhIBEACVXJstPdymc/0ZAQYWSy/hOpHFV0YBgon4ymgIrN0xlJgW0Lju\n" +
            "oSW9pHen2MWEdLTUJ1eXrj10QPkB1oFpilzQFqXRYTxjrbeoRZjDXoGEf7JTFcIx\n" +
            "R/i385qreJ2ZYw9pUuBCW2R3juiUwzwiwC7/2y2qADOh9TPnJyyoPv3oDuGdLd7h\n" +
            "ge3loYOySF0d0JZzFr+x3yQNDWUibiJbckZ1jFpLV2oyHNV9lpxH22xW/nhmanqR\n" +
            "vFe6PZCK4UNQBuqY9pvwp7neoM4j5h862LSuEmG4LjIaYp2DBf31jIsWYk7cCgcP\n" +
            "p+t6/9/AGwA05n36G2ncnrcrNX25R1F8b0tqZgEe/fOJ4dNCSTeV4pqSotxxeKFx\n" +
            "dqY6kvOCCauS5ZLjmMUimgOkDk7/3ePEcRoUMpbhETs3hOcfMMLsh81OL8FdvZVc\n" +
            "xxoYmT0ca2kDwixSQ+lLfDISECIEW080H7J/bez3wSjYLOfypNIGCdrZ+9zwtHYZ\n" +
            "QxmziDnjprkDmTXKYA1KYvPXhfxHBpmn8spI1MJawHhF7zI9pycWvWc+oty6+/B+\n" +
            "dVrx9G9TNDl4xDctehCXC9LErVUW4cAJxZlft1dFc/49JpSRPWzAcw8Q5XOZb2yJ\n" +
            "qjUnzw690T0COD5CCM34Fh9/ZcDZXBF/WJT9lWMDFHq84fW2tP+FLAd68QARAQAB\n" +
            "AA/7BdEpGGZgyF+bRQ5tjQ/sk3PTTY4/Y1VELlsjsukyMpLvWwqFL7YGLd0D7ZbB\n" +
            "sPQipS7+RSGiGK79g7Bo/3h5P0yo58vgedLzZJHuIZD14yuRNGJg9JTK/2ioM3MF\n" +
            "IEr9XkRXof33noU2uOR83EjQpWJR5JCrC7m5bCoLngA/pa2lF8wIWPWiE3lqeaN1\n" +
            "c1dpiwRUMiDXDjMUjamGz2zwVY+omWdg8wawdRQY9HhIcrLo2YRE6Pwe2cAGd+ib\n" +
            "oh6pPSZA0h4vw2RPFixv0IjnSiHcVtUyjYu3R4aqN2MvEsLnACbb04sReFh5MsnA\n" +
            "0YHQkjcTGzNYCuf20SQRhl+HRLq2xJnKzZsjYjElbnOuEDuyeMAgHs7/CO7+72t3\n" +
            "LCjrEX6JYi1tuNdbu43BFn9TM2aH5ix+XK+/3ZKgmM3fNaLZxM8041MtGtdWTNnp\n" +
            "gySKhyLChC/2R0p2MY6fAzRi045ED96fSaKpfroHn0Lw09rNlvEwD1rGHQyGHl0c\n" +
            "rBWHO89Gpfx6lBOuyC+kJG0Cm5BJkXHpFJ8ky+xoEDzHUgNdXsAvEyj2Dqxkzojz\n" +
            "oC9M7vS66p45wXXsbEcGCG/FCw8XRNaeOUKOBgQ19IdTsoqCPBfcqWYMkqqcmcwF\n" +
            "62eT/A8AyHrAi+srJawQCAQtrWnQ9A/oOapqPyUhH/QdjAkIALvoejVUd8OwUkHt\n" +
            "n/C7mgnoAlPBPPlQrCYKR4bZdCkleWjaz8zUXRKSfTWn1rXDHjDx7SR7kykBqLFZ\n" +
            "tzkXx/dzB6mOS8Mw8t25Asn9kocMlYQebLDf2jw1HjeC9q8+SY2Cub3YQuVJdZI5\n" +
            "eu0Bo4DgMn1EmQPuJSY2DO6tHu/kyTT35oJfJQ5ntYPUSWMLBWYV2tfcHx3UkaQt\n" +
            "nXTuiL7IfEeRniv1I6b2xY5So+WbPuSQjSbmqGfGHythzNmAZsWmCXFZFHQqnbHn\n" +
            "DtZlqzjIJmaJK6qNLCcUC1ZC6GPU7/n09Q/n/Edu5uMi3Ktc+50CPzjs8x7q6ipb\n" +
            "e03Hqh8IAMt8VAIC6EeFN2MoyExT95QR4HXzDC2iHFLYxzVpaBrTJ9RlVlStTe+a\n" +
            "W5euSHCWhGA8Nh8+s4NHLkYk3LezC89+japsooVU/F2QHfEuHWBtevw04+vub8KG\n" +
            "eRg5+7RK0DnCK3MM/yi7/06J+JTV9rAe3qyaCX2mGQK8QeoC3ea6Gk/d8HY/q0y6\n" +
            "LFP/0PIiyA55nYdZQoSEFEfmg1lJIU0h9D+FaoiVYjd1IVnHlcooFReJ+SudY1rV\n" +
            "UP4mckKlgbyfOmB1G8fehTGohfRCWCx92pKKk9jxsLcY8jUJpO7Utzg00OwJWRop\n" +
            "QyajNCChzXcJju85OEQS8noBIGk7WO8IAJude9ei9+M4sKGUN42aRcX2njLggajH\n" +
            "0BoqcCP6WJGZ+08kZY+PhvUWAloFm/icOtWRJJbgjvVKZU+yoFjdPu0KIDCYp7pZ\n" +
            "3SzUoZeY8tt1dNCZfcsJB+WeYW3HQXAavUP4+gR8ro7WjNQhvWddLgHo1z+rNoti\n" +
            "1BUFlQkVKdreM9ll3HUpYy2xcKMylOxMeL/qEbRCO5L7hDGbjLrio3ynpHrVLIi2\n" +
            "+wWU+JB2pVQnI4+tm2gMAil63wu8WJZz8BVxn3AhAQgQIH9OfuRCpPwvrBDIAyog\n" +
            "T8razUcCHQtulj9Pchu74isreAwMn1Z4Ddol89ANfIKn14mla1WaGx5wiLQcQ29t\n" +
            "cGxleCBSU0EgPHRlc3RAdGVzdC50ZXN0PokCUwQTAQoARwUCZhAGFQkQr+RnsppB\n" +
            "oM4WIQSs/H/6Ar7B6FACLTWv5GeymkGgzgKeAQKbAQUWAgMBAAQLCQgHBRUKCQgL\n" +
            "BYkJZgGAApkBAADrLw//U5KEArVsiOmsK02Fru9BAAbFf2+otw55d5UFNCd/G93T\n" +
            "n38lTuThl9Tk3dLGd/tL39fZjB7XlJ2eBcV/8uzBp9F3d14j/GDwkx7gkaA34TMr\n" +
            "g73XnIdw2V88WEuKhFg0JAGUm6C8LEtlHYie7kS+gDtyQjQw7qUGhCG/QHyIi0iO\n" +
            "DA31NCOSHJI2rhK8nkS6SGGzUDwWEP92bKnlcqtooCwdEdPuRuNCJ6J5GDdhX06t\n" +
            "ZngnLRMHt6pN/UDYdNNVJaIV0ZFICMRTPJSSHzIV59cQx20DBZ7cYK2ag6uDx+O+\n" +
            "tVWamNcb9JR5TuN7PX+Q/EEhiKpaom/lFNcQwqj4kclwraZXQ2HaHDoJoqCIaBVA\n" +
            "4eGG1nCy2weEgrSPk4GxFjqAiaifR3Y75JqPG8VTpS51iKU4gvs4EeU/8+WFBOjp\n" +
            "lZH7FAS9vqCPltZm/6hTD7phqRXAZe3J1RoxFFAl3ikzz1Wz7y/m/y4ouz3bIgRR\n" +
            "gjFmjPYSbh/p4SMj1jELebs7klqp7hKsXFP+mZm/Oh8WK96G6IIt/TwWJ6exOB1Z\n" +
            "pcS9RiFOGjfpIy0xzMOGj9EFX3qs+jwpc+oRRCAyqRZZNrvRCgY4crHVBQa5AyJb\n" +
            "TJ4OfofY8Lj+MBNJO5M3FpljnjP89JMxFqtYGzj/qtDv9QFWXan2zbMRfb8q2kWd\n" +
            "BxgEZhAGFQEQAPqHNmUHC6rw1y/1uXyd0Y7NoprEB2TAWoUxbX3ZFfUCGh881CAU\n" +
            "8JQiTED5yXZRbwi4JQSBXg+yRjx8puB5AvHAvZn2AWreXaTyDfoXMXg20qm5sp2V\n" +
            "mVmtr6iI5rXifa0I9kMJvW0jNNsPFgXuo3/1dTM7U11/HDzdmh9arKGB7MnQphmV\n" +
            "T3L0wFhY9lHMtNn3CmiTqJNDJhHWTMTWeOictqULwIccFoQJEdBzhJZE3+KX+yv/\n" +
            "a74DJoSa27SQjJEGUmXCEx3GZiwwGP201hP5TKPLLxfd5B+W+uGbPP/T9O3LEDNp\n" +
            "hUXYmuKSp77+Zq0JHWnvlSvKDr4oDQ8Wgiq1iDD1baYY1EWmn5olVwyi7jS2m5mG\n" +
            "fMW7MFBssG1nbmUama/pPLqcV4nr6URveGDFwcx6/ulMkN9P0C1qR3K4Asx1ZB49\n" +
            "Kt+iz1fuzh+lFU35DS/wRT9LyUzaSvaGegThHNAhw24m19vb5mrBUtQOGuW0MCEh\n" +
            "CzWkhjMaQVRbCrUqT+ab+X/2xA7ETKITtq40IAsk3tW8YLnKfEt+u7BMMGqPJV9D\n" +
            "oVRQZwW+xc47T6KfmNEw2RzkoxbmZMnSUBjp0MFWs6Tc9a0OMqnwdbrsxlN1AP0e\n" +
            "XhpRs8Hl2TuloY9j1yDW2aZ8l1g0KQMbkPKH9dgf+XR0+un1p6HsJpRHABEBAAEA\n" +
            "D/wKn48r64eQIRRO4VGTOjH3pzqc63EQ0aNFAJqO+pSWxhcLeg3YqmqlLWskWjMz\n" +
            "xDI8IWrYbQ/rBHk7+WEuJZN9YtnnXGok+PbplqYHE9KyMUjvj4NGcWCGT/oh4GRA\n" +
            "FDGWE8o1f4U7yoFkRJh/eeYO9/6XRI29ajVtU0xExhiJ5LOAv0s7zHwI+N3rISKY\n" +
            "x2Bn2bTkSFaen/tOSFMLCbkoy/RmvT/VutgtkyDhQPS/Vn5T4nPxIqyT6xhICTUF\n" +
            "zBdZ0vXNgNREr/QHLabxoyhswmaAj44Yqf0RZdqPlICarIc3SiQOugu/sXan4uYg\n" +
            "EDOUZM2Nf25I5BGJ+LLND/xG89865BzCiCLtIii6HnB6fabbKpPIEm6JTL8NuS7L\n" +
            "rjcWefeWWSlrAOjZGC0OySxIVRLWnE3Mw0YLhWdqdb/zit9dP0tYrezdsRmX6I9D\n" +
            "eRpGHKhFPLwyuv9Q/7opJqBuj8OmuFBQxNOipr9IKF2OJkqLBcy92rThIETliW5G\n" +
            "6xF7wVYe4leEGzYrp4Zi3meO+CJoyw2vVj7RcZKU9Lyc3MR5VxHjl7aqrfhgtpGS\n" +
            "3YEmW0O58guXc9hdrVE/dy7r0pW6CZo08w+dv2OSOyvjTdq8SkdE8cKJ52eipR/3\n" +
            "SbNIu3sgd3+keXqvXvvhIHjvbqoV/c4cMnzj4FaR5w1xuQgA+18DlzS2+BocmotZ\n" +
            "4uhQPheFrQsmInawLOVDVjMIf1si64DrjeKC9+3SjJseTD3nIy26/s9kOI4ixkjb\n" +
            "jO4J2/fNxyT5AK6Owcpy8wTOkXaI8MAhPq1IWq8dAZFnWxJNOheNx5HJwhx4Dvrn\n" +
            "z4ONDFfKBZ6eSSiak2eJ7B07jjyU1yu1gAXRjc61cZKK9V1dY6/HgJzuzEXLYqpD\n" +
            "MXHz33Uqkg1qRtkqECx2i7Vo78gZcASB8fAsE7Rinub9dJlfdwWGMgwOU88g/aMs\n" +
            "KaizN4fosqpX+Y+0uofl40lpKQFcmJOMCxCKZeaBD1+UOu2jIgI4UcRfh75FyQn8\n" +
            "zzmCZQgA/yQ5fwyQtwYiUIlmwAdKzHDoknVmYdlWwBjlFhLTFJccIjGzzGePN7nE\n" +
            "iwxJfX/LZ4ObprT+q0nfIf37cPqXfPv35S/yutLCX5CjkIsiD93aCsDE58/WlwFQ\n" +
            "oxi62pAMYl83HfHLtyRFFuXmpnt+Su7tlzEYCRn8JakKy/VzyEEbjRiQgJoB/Mje\n" +
            "GGlbfY+huTCGM40gtAduOzt15Qxr4JY1QLArX+Dosf2ylAoXcmcHz9wNIAAb40fr\n" +
            "fO13k5FqXQDJh5GFSOQliQX98D5ip1SDK2Ut8EDuq2NPjMbfI08vf9TELhEmTXy2\n" +
            "7rCM99in9kFQCkKH7cgTnihyY9N7OwgAmpnlXADaiCQGB7V1QQWhiJCPPB0ptFQi\n" +
            "ZxFDgJ8cqX46Wg7cK9pC8uLpYMpTGIGQonygKEOVf5QY3CP4mZ2WujCQ7m4sDpw0\n" +
            "tkpdjTkhz4Kz1xw07toxKiqSjwlKq7TLm/HbqNZLijLLyvjTB1xxlwh7XCAaXzr2\n" +
            "Ri4dBHVqQIO/sygBVSRPHVqT6nKjo+Bz+qb7Bef71jkANrmIRjzq66X1fYlrQejd\n" +
            "4W7/+YNzOsKHcgBoF6A1texG59JH1raD5GVnBfFLWoYx4T57oN0mK2+BDSNCQSYe\n" +
            "/gzxxdbocaWMjW71JBudLKh9vXwhqPLD5828YkTJWCyxIAjk/6BtSXxZiQRSBBgB\n" +
            "CgI8BQJmEAYYAp4BApsCBRYCAwEABAsJCAcFFQoJCAvBXSAEGQEKAAYFAmYQBhgA\n" +
            "CgkQiw37fiqkMiCWGxAA99f7sR1epBqiq1oYVOQoj6ZK/Vzstbv31vx1evQSy4/j\n" +
            "9RhD8pNZWg9Kb2U5vv8ZZoJGBNm071P9/sZE5YJm/2GB7CStC3z5WvHPQZK5a2L5\n" +
            "d8jp99+fkK87qlWbig4AiRD/nhaoHshsKqp9q+5NEypZapZleQ2HIJ+wW3aqjtj+\n" +
            "U54JZiXxd95pMbx6JMee6SvpKGZTceem7jOljFwMZ0I+qPmaFpALJfZI3pxKCozg\n" +
            "72yABVk4ICWJ5xZuxfUvoIkCQ9wcw+D3xYaHWQ1jl8l/mzZaBefa4ZlSk//ajgPY\n" +
            "HhDrEmhKTQ6Lv0aLC83pVo66IRDZwCrcYFy2cEefxX3FHqGr6sD/cPMMlu/aBzG+\n" +
            "oAvx3Xseav9zv5eZlRET4MD8QO7bPC7DeGdBPOhKIAoiFCOB9hIlr7MTNFpQkpcn\n" +
            "dBovK3s21+E2cAzPuhrBuHKPXeGV8bHPdmtZk5wtaBfBwwbtAzirGQOx/aimDK2y\n" +
            "Tx1Kjyqb6QCdjJopzLLtBGd9PQcpUPenngZ8+8uE2inNlZRczEfB6YtNitAtIx/G\n" +
            "qkD6DagReyD/gmqQKUGn/6amYkux9dAs4sD/F1NN1hN4BWlvhpXVkiqG9/1MAu77\n" +
            "n+ne74CJcWJ93fKokMvubyusVJfZfuQuLYz0NcwxN3YMlt8yDL4l0ZK+GEjXd8oA\n" +
            "CgkQr+RnsppBoM7aUQ//fnTz/4jFGqHssqp3ZQro8Ie4NEmtmjioFzq9FZQX5KAZ\n" +
            "uL8q6pT1ChV6uqvL9YgfYgbSGaWaVRIJlt+cfz8EfbHpgHvEj1R94TudE0MajDdR\n" +
            "1V4jpEIHtlftoN9m9n60woAFScN+7LjQ/TRZDf2Ie6lBkpTEHr1gUvb/VzyiOSxg\n" +
            "sYMbcPPpcymCPJKyzx2DHFryHRS7YzoRHb8Apmlat8ceervNTPzErznsN1LljEA7\n" +
            "qhghWgkCrpApTGOESpwcoGli6m62tDZvLzpIJhHK3yan6nC7VcQ09FHdMJc+762Q\n" +
            "ZxPbtZalnCrxrh22F1KcJwMYBo+PeOXueL3fCiPGImEe2DT1SIV8wmO5yCffxGoF\n" +
            "ylGotT6HrGQPseB8yo0WycVs9PIhyLPc1D6SVerLQn34ru0DxuXX2P6x0UvXxH74\n" +
            "z2VCGj78oBv2lguy47d3IEllWhFTJUHyH+KR7gUQlH4f4S0/drqH0s9oLl/xGUET\n" +
            "9IHDK/aPh57DTdpyNur/75cty8f94ScmwclYB7L+z1wMMDe3qA9GhVG9UvL1s8oz\n" +
            "OQ4T1XwKMf5a4obCkOoyV7B41RdwaKHYVkDGcqvVbQJRQGpyE8fzqFakjjdVN0SN\n" +
            "diyJvSrr60QeUdnykTmQRZK+hajAz0hKSHT9L9bhgwfMUDd8SwM8D/shHgvVffGd\n" +
            "BxgEZhAGGAEQALcxdafRMdeNOF21Z6AFLIJ4jcsPcgsJ1sTpMHHJCGBfHB5iE5VF\n" +
            "LbCYKMES1mhe58JsY2KLDj/9YgzJKfO4tn9SXVWmMCOsVoa9N0OH0H2/QxcipjCt\n" +
            "LNFg1nOYVSq47TmgAMC+NnAMPYBh0MlZrr++Z4WFxNxKukNmvlO2JGRTMm+p/6qr\n" +
            "zhXyBaVxI2ZW6wqg79JAFKfC7v2b8Zfp7t2ehlRQ0gweHLOFBjIhaZatk93J9pF4\n" +
            "epzI6CuBLMwoFKmj/bVbrZPPUabe8vMJt/sZjxQzzfKLnHVRfihs7InFGaf6wgxF\n" +
            "7cDDA5/x0/wsmOlOaxyt5nInJnMLdUzmIBVu95YjAaBFejF8t9JzhOgDXQ/A7Zx0\n" +
            "EQHDF56FYvIcHVjUCJ4qeLJYCWMNAHBkUbyCltMJnFB+aYc28eOQW6fHBczo+jmr\n" +
            "HNjsg+1RWal1ZijzAmCN1aAHY9DPvUZklLn/qpk9EtpI6hLRP94sbbr1bJzibBi9\n" +
            "mEvsL8TwhpEqwc+HIGqnvVQHqb1mVEmcGVdhiqmNFe94lyYkv7BWim5mu6b62Dkl\n" +
            "wTAcpAowYzqkZ9UXqBlHMGqrFqtSvT6PBh+s7ZCd1/ueACV5bM9G9lU5DRZOcuAS\n" +
            "dM0TI6a04PEziV1npOFxcnx+sZApDZ8Rqpa7nkZXsKmxhRoupUi4neAFABEBAAEA\n" +
            "D/4//TrHv77VODL0KKVls+j0Of/tahu/11P5vCp71GjkoNRFmKSWg2+OO9ggeOAD\n" +
            "3QK/WvTsOv5jQ7K4HJxW0bKNjsujW0V9cHlY30cqg4pEIkbhEe1TG2qISHcgMZmu\n" +
            "LqJOeqFIsih5wwzIh2JSsszjlTK75Rn6iO+/E2hv/TOBB76aWps/lnuKFtv6Cib/\n" +
            "XGUFdWnP2ypb3y9zzsD4+3HAX9s0IHb+XJZR7qlXYWxsgX0g/6bs8VSC53qRl7F6\n" +
            "LpXpG6tHahqbgtNWopHiawak4yyjNeU+T537LNgQbtvA0+Q+VMzrVJHTv0rI18Pg\n" +
            "VgOjmwy3G9dfEGXR0bLLhaa2vfvBA54yXTfIN8qn6iJctxRucfJEEYWWIcdXQNmv\n" +
            "aD2Ozz0IzDDSMyyZiAibhuoOOL4izinFX9O7AxVEkIf3+IHloxjuT6LSllNOO8ZB\n" +
            "xKsyeLFgIjQFXjY4sR+JleML+YkCq46NdHVmbb6TryDelkduqCHOk2PGvdv/1zrf\n" +
            "yTRMWQLx80Urd4rOKxNOnqwblj6yt1eOINXA31GkJSIEOkkLdFOZ/H7zp+UqbGE/\n" +
            "4nGh/JzBur/jTLIx9ElsrV3lLGEtUa47mgbMYAXIIL2RR+LMlT4JoO3SQXEuvkok\n" +
            "RT7NpyoVTWHYlQiR0XruCt4bvWaEVCdiNj565yI7pqPzkQgAxZ5tKTPW+8uHOQSh\n" +
            "NuY9Ok2bUcaNvzboOu7t3c9rETf5/XBAjcmjNSxlDLLiZv9Qp3DhcnXu45ZDSh86\n" +
            "Sd+o9NlQLTAs/J98rRExDISj42V3q740Hf8jXS3lz4fwlr3YHeV0c1A+YsIoY5nb\n" +
            "Bs2UHO5nX1PgtE17Bgbt1+Y3jamK/2+W7WDAiIq7G4uRpeORqrXsjWZDuIaKR03C\n" +
            "lxj1c7LqkFUjVpY47mdlBDuXmra7slcYVdabR5oULpRvloAjp+VX3Yfwzl0/I0o6\n" +
            "/3WZTRhM4PhkP4imkveykv/BkIDFWfho3pJScru8Aqn3XbccrZO8WY6nONzvYIr+\n" +
            "COgWpwgA7VALxeELI7nJiWeZUZ5HBHOMKQFTdioKD9BgwvEPDOXq+VqAT2n3basQ\n" +
            "ShYjCot8gnxe3ei+/KQs/a8DkZVDY7XKMqhZyvidxF6weFAbO4Z+sB6LfyJmz5D1\n" +
            "nA0iv8laP6at1wgn1MSfpXZm1cXuUHDpyTqWXLxG1qbUpQJS27fl6F0ws1k8Qvno\n" +
            "PLjGbsbEeujbWU2lqZDs3L72e/arIpHdO94LNOwSKrGjO1KTkGgue+uGm1u17gEZ\n" +
            "3U+rbCvG2lTq7kHZEQHiGaIygxyDJAyIvroPZ9c5nABLGMoH93Pq9tGX2OPxyWLx\n" +
            "P1db87EzKRQjFGmZSeeKENRvLYAVcwgAqZTCPD9CkUG6O//rZI/1pPArhN8CY/+x\n" +
            "8L2jksvaTLimdBzXyVXlNAPIynMih/QaxNq+WNOmnihVFAw7ur/nmN9Oea33Ue7v\n" +
            "6Ryrz9nzi6GonLz0/grzB5XWAiO3+i9WUdVpeTgjlFPXSJsbOjEVRAB2W0heioeM\n" +
            "M6weKP8i2O+GF3ULoWzmam4EgsanaSCXgDq1RYXyJhfUYTikVqrD+qJYT0asxU0H\n" +
            "S92KmdZ6UKLOTPZdrIL5X0Cj/ejBX/94xHLM0GfXT9CIHTVIVSa2poSbWhN0O+yT\n" +
            "NMySr7OHGDUjEUqBL2O5Wm3oyMK/5EoSQ9YJBCrkbkymvoahjrooXZSeiQIzBBgB\n" +
            "CgAdBQJmEAYYAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQr+RnsppBoM7gBQ//\n" +
            "YGQ6suANXV0C7TvofcMwubahLriBiWGAkI+pNQ7Tmzgql4ALcf4BFsDffcTCy3ue\n" +
            "dLAZkEEwT86Ip1qW7mKCN1tScj0g8uU8U78oVShqoyEq0ebemaVmY7gvFWCpGXgr\n" +
            "JgNjL4QzRbwzKUdvIkTMmUDiPqhmGuCFV76pazzTmhI/RAzVfnroG0kVDVwODlCI\n" +
            "CcswoEOI32v+B8SJbbsXXQ4E6jrDwPIUV/z54VERbi+JcKaes0a/rOLF0FOnoTFs\n" +
            "2b2aqt+Knj/RQCP9r3UNl06dONBMaydkhFmMjRjenQb6p+91JyNkXJ6tgD4CDbps\n" +
            "2kqryCpZf39E0QU75Rvuofc8vhSRbRvSl7D+NhOdk9c6EEOJPbtozaG+/l8g1K42\n" +
            "aMT+TvccBPK0b4EcZtAyCLjDg0eA/GN5+DIhBQCQA4y4KdEf3IMoS+BeEPBNfNyG\n" +
            "isVD/f/R/68uGg6S9sKFXOCAXO0rnVIu1Oe123l09FsXVZpFDV3PMbpk7Sxh/20L\n" +
            "ERTp5jBV+2J2szmYYxcSfVl6h+P3k8Y8l4evEoPPL6Skz9uZI5C3UB1c6dnWBcRm\n" +
            "G759QEMpJuvyuwFZkcoGxfVvtneZsTGajEnNOB4o46hb9a5DLJ9tc06zG+j+eUeR\n" +
            "C6mwvn/JYRaGr9uG4zpdxNeFmQ80yitmGGllHenjfaU=\n" +
            "=hhYV\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static byte[] DATA = "Hello, World!".getBytes(StandardCharsets.UTF_8);

    // Signature by primary key (shall be rejected, as the primary key is not signing capable.
    //  We instead expect the signing subkey to sign).
    private static final String SIG = "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iQIcBAABCAAGBQJmEAYYAAoJEK/kZ7KaQaDOH4MP/2kaK8lQaBU+jChpWPLR2R2+\n" +
            "dB7j29tFPRAqbzbazxaF+jZQxuuHWtM3bwd9Vdta9zirDc27b7XyufFLBza4Bn+R\n" +
            "7fT7uHTQQts/zaX8YGxJ90rb06toFXiv/rlm531kLaGXxlACU6SpI8maqpP4im+G\n" +
            "W0LgBDZiT9udFs3eeJZ8O3yDLP29Rdw8sHPa6pOyyhkkhsvo0bNaBaSt6GDW5UK9\n" +
            "f5Gz+XF9ZLJgsNqQwWQM55+4ZhdkfEszRcJgAhuSCamk+ZLfvIPhEu21/7weNq3c\n" +
            "Yp0hvaz27gaW7IkjEgI1FqkPrmJmyk5SVMMvaev9p0WXDgUIeDLI6CwvoXaoMCAX\n" +
            "pg0Q754ccHu2pELwNb5YIxGSPSMXRVH8xUDqicZpl/50ucy3g348s5HekcVnzBtX\n" +
            "UKVX3tU6r5HrkVAX7bDGht3WXE1jRE98W3uKpFWzrJBK+uQIyOtOEXeKT+z1BbNy\n" +
            "CvYeDq4xjpGYB2tJY2LKXrC4+IzJ56e3XU2t75KhO0SBV+Ax1bJ0MBnmAedg0pg5\n" +
            "0r+mknBqoYu+OHNwMS/N+YH1iZEV0QxP+ldLp+ff2QiIvtiDcOIQ0oNEJy0bqh0p\n" +
            "TrS9PKMl+kH+FaAPUVb0ruviTd/zPljjiJ2P396bu1JBXdoncn2y4KklQOWHJSVI\n" +
            "F5ZjatEBixl6pdW7I5Cr\n" +
            "=vPG/\n" +
            "-----END PGP SIGNATURE-----";

    @Test
    public void testSignatureByNonSigningPrimaryKeyIsRejected() throws Exception {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(KEY);

        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(DATA))
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(PGPainless.extractCertificate(key))
                        .addVerificationOfDetachedSignatures(new ByteArrayInputStream(SIG.getBytes(StandardCharsets.UTF_8))));

        Streams.drain(verifier);
        verifier.close();

        MessageMetadata result = verifier.getMetadata();
        assertFalse(result.isVerifiedSigned());
    }
}
