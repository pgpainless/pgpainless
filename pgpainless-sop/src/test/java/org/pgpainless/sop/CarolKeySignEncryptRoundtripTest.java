// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.DecryptionResult;
import sop.Ready;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CarolKeySignEncryptRoundtripTest {

    private static final String CAROL_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xcQTBF3+CmgRDADZhdKTM3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0\n" +
            "OJz2vh59nusbBLzgI//Y1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vh\n" +
            "yVeJt0k/NnxvNhMd0587KXmfpDxrwBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0Uj\n" +
            "REWs5Jpj/XU9LhEoyXZkeJC/pes1u6UKoFYn7dFIP49Kkd1kb+1bNfdPYtA0JpcG\n" +
            "zYgeMNOvdWJwn43dNhxoeuXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8MTBqvPgWZYx7\n" +
            "MNuQx/ejIMZHl+Iaf7hG976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9\n" +
            "+4dq6ybUM65tnozRyyN+1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpX\n" +
            "duVd32MA33UVNH5/KXMVczVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0\n" +
            "SFhlfnBEUj1my1sBAMOSO/I67BvBS3IPHZWXHjgclhs26mPzRlZLryAUWR2DDACH\n" +
            "5fx+yUAdZ8Vu/2zWTHxwWJ/X6gGTLqa9CmfDq5UDqYFFzuWwN4HJ+ryOuak1CGwS\n" +
            "KJUBSA75HExbv0naWg+suy+pEDvF0VALPU9VUkSQtHyR10YO2FWOe3AEtpbYDRwp\n" +
            "dr1ZwEbb3L6IGQ5i/4CNHbJ2u3yUeXsDNAvrpVSEcIjA01RPCOKmf58SDZp4yDdP\n" +
            "xGhM8w6a18+fdQr22f2cJ0xgfPlbzFbO+FUsEgKvn6QTLhbaYw4zs7rdQDejWHV8\n" +
            "2hP4K+rb9FwknYdV9uo4m77MgGlU+4yvJnGEYaL3jwjI3bH9aooNOl6XbvVAzNzo\n" +
            "mYmaTO7mp6xFAu43yuGyd9K+1E4k7CQTROxTZ+RdtQjV95hSsEmMg792nQvDSBW4\n" +
            "xwfOQ7pf3kC7r9fm8u9nBlEN12HsbQ8Yvux/ld5q5RaIlD19jzfVR6+hJzbj2ZnU\n" +
            "yQs4ksAfIHTzTdLttRxS9lTRTkVx2vbUnoSBy6TYF1mf6nRPpSm1riZxnkR4+BQL\n" +
            "/0rUAxwegTNIG/5M612s2a45QvYK1turZ7spI1RGitJUIjBXUuR76jIsyqagIhBl\n" +
            "5nEsQ4HLv8OQ3EgJ5T9gldLFpHNczLxBQnnNwfPoD2e0kC/iy0rfiNX8HWpTgQpb\n" +
            "zAosLj5/E0iNlildynIhuqBosyRWFqGva0O6qioL90srlzlfKCloe9R9w3HizjCb\n" +
            "f59yEspuJt9iHVNOPOW2Wj5ub0KTiJPp9vBmrFaB79/IlgojpQoYvQ77Hx5A9CJq\n" +
            "paMCHGOW6Uz9euN1ozzETEkIPtL8XAxcogfpe2JKE1uS7ugxsKEGEDfxOQFKAGV0\n" +
            "XFtIx50vFCr2vQro0WB858CGN47dCxChhNUxNtGc11JNEkNv/X7hKtRf/5VCmnaz\n" +
            "GWwNK47cqZ7GJfEBnElD7s/tQvTC5Qp7lg9gEt47TUX0bjzUTCxNvLosuKL9+J1W\n" +
            "ln1myRpff/5ZOAnZTPHR+AbX4bRB4sK5zijQe4139Dn2oRYK+EIYoBAxFxSOzehP\n" +
            "IQAA/2BCN5HryGjVff2t7Q6fVrQQS9hsMisszZl5rWwUOO6zETHCigQfEQgAPAUC\n" +
            "Xf4KaQMLCQoJEJunidx21oSaBBUKCQgCFgECF4ACGwMCHgEWIQRx/9oARAnl3bDD\n" +
            "6PGbp4ncdtaEmgAAYoUA/1VpxdR2wYT/pC8FrKsbmIxLJRLDNlED3ihivWp/B2e/\n" +
            "AQCT2oi9zqbjprCKAnzoIYTGTil4yFfmeey8GjMOxUHz4M0mQ2Fyb2wgT2xkc3R5\n" +
            "bGUgPGNhcm9sQG9wZW5wZ3AuZXhhbXBsZT7CigQTEQgAPAUCXf4KaQMLCQoJEJun\n" +
            "idx21oSaBBUKCQgCFgECF4ACGwMCHgEWIQRx/9oARAnl3bDD6PGbp4ncdtaEmgAA\n" +
            "UEwA/2TFwL0mymjCSaQH8KdQuygI+itpNggM+Y8FF8hn9fo1AP9ogDIl9V3C8t59\n" +
            "C/Mrc4HvP1ABR2nwZeK5+A5lLoH4Y8fD8QRd/gpoEAwA2YXSkzN5rN16V50JHvNx\n" +
            "YGiAbT9YNaoaqQn4OdFoj0tJI4jAtDic9r4efZ7rGwS84CP/2NVTISnyFmG6jHCG\n" +
            "PpVm7Hh45edq6lugGidEx+DYFbe74clXibdJPzZ8bzYTHdOfOyl5n6Q8a8AanP5e\n" +
            "XFQfqdKy/L7PJMaIx1wIuVd5KDNFI0RFrOSaY/11PS4RKMl2ZHiQv6XrNbulCqBW\n" +
            "J+3RSD+PSpHdZG/tWzX3T2LQNCaXBs2IHjDTr3VicJ+N3TYcaHrl35gBIQPC3c09\n" +
            "AtDvu2pFzilq34VyfDEwarz4FmWMezDbkMf3oyDGR5fiGn+4Rve+iCx/jQhoipIY\n" +
            "nXfRiLgP1rXh4kG1y8n4kOJ/D9dqvfuHausm1DOubZ6M0csjftZt61Nmv/i8tyQo\n" +
            "eE3jtu8PnMTFpGnh8k0GiVTGzGw6V3blXd9jAN91FTR+fylzFXM1YuWrFY7ig0qI\n" +
            "yQ1dUMF/Is2TZdbfgCNC922pQmm1dEhYZX5wRFI9ZstbDACH5fx+yUAdZ8Vu/2zW\n" +
            "THxwWJ/X6gGTLqa9CmfDq5UDqYFFzuWwN4HJ+ryOuak1CGwSKJUBSA75HExbv0na\n" +
            "Wg+suy+pEDvF0VALPU9VUkSQtHyR10YO2FWOe3AEtpbYDRwpdr1ZwEbb3L6IGQ5i\n" +
            "/4CNHbJ2u3yUeXsDNAvrpVSEcIjA01RPCOKmf58SDZp4yDdPxGhM8w6a18+fdQr2\n" +
            "2f2cJ0xgfPlbzFbO+FUsEgKvn6QTLhbaYw4zs7rdQDejWHV82hP4K+rb9FwknYdV\n" +
            "9uo4m77MgGlU+4yvJnGEYaL3jwjI3bH9aooNOl6XbvVAzNzomYmaTO7mp6xFAu43\n" +
            "yuGyd9K+1E4k7CQTROxTZ+RdtQjV95hSsEmMg792nQvDSBW4xwfOQ7pf3kC7r9fm\n" +
            "8u9nBlEN12HsbQ8Yvux/ld5q5RaIlD19jzfVR6+hJzbj2ZnUyQs4ksAfIHTzTdLt\n" +
            "tRxS9lTRTkVx2vbUnoSBy6TYF1mf6nRPpSm1riZxnkR4+BQL/jEGmn1tLhxfjfDA\n" +
            "5vFFj73+FXdFCdFKSI0VpdoU1fgR5DX72ZQUYYUCKYTYikXv1mqdH/5VthptrktC\n" +
            "oAco4zVxM04sK7Xthl+uTOhei8/Dd9ZLdSIoNcRjrr/uh5sUzUfIC9iuT3SXiZ/D\n" +
            "0yVq0Uu/gWPB3ZIG/sFacxOXAr6RYhvz9MqnwXS1sVT5TyO3XIQ5JseIgIRyV/Sf\n" +
            "4F/4Qui9wMzzSajTwCsttMGKf67k228AaJVv+IpFoo+OtCa7wbJukqfNQN3m2ojf\n" +
            "V5CcoCzsoRsoTInhrpQmM+gGoQBXBArT1xk3KK3VdZibYfMoxeIGXw0MoNJzFuGK\n" +
            "+PcnhV3ETFMNcszd0Pb9s86g7hYtpRmE12Jlai2MzPSmyztlsRP9tcZwYy7JdPZf\n" +
            "xXQP24XWat7eP2qWxTnkEP4/wKYb81m7CZ4RvUO/nd1aA5c9IBYknbgmCAAKvHVD\n" +
            "iTY61E5GbC9aTiI4WIwjItroikukUJE+p77rpjxfw/1U51BnmQAA/ih5jIthn2ZE\n" +
            "r1YoOsUs8CBhylTsRZK6VS4ZCErcyl2tD2LCigQYEQgAPAUCXf4KaQMLCQoJEJun\n" +
            "idx21oSaBBUKCQgCFgECF4ACGwwCHgEWIQRx/9oARAnl3bDD6PGbp4ncdtaEmgAA\n" +
            "QSkA/3WEWqZxvZmpVxpEMxJWaGQRwUhGake8OhC1WfywCtarAQCLwfBsyEv5jBEi\n" +
            "1FkOSekLi8WNMdUx3XMyvP8nJ65P2Q==\n" +
            "=Xj8h\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String CAROL_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsPuBF3+CmgRDADZhdKTM3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0\n" +
            "OJz2vh59nusbBLzgI//Y1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vh\n" +
            "yVeJt0k/NnxvNhMd0587KXmfpDxrwBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0Uj\n" +
            "REWs5Jpj/XU9LhEoyXZkeJC/pes1u6UKoFYn7dFIP49Kkd1kb+1bNfdPYtA0JpcG\n" +
            "zYgeMNOvdWJwn43dNhxoeuXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8MTBqvPgWZYx7\n" +
            "MNuQx/ejIMZHl+Iaf7hG976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9\n" +
            "+4dq6ybUM65tnozRyyN+1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpX\n" +
            "duVd32MA33UVNH5/KXMVczVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0\n" +
            "SFhlfnBEUj1my1sBAMOSO/I67BvBS3IPHZWXHjgclhs26mPzRlZLryAUWR2DDACH\n" +
            "5fx+yUAdZ8Vu/2zWTHxwWJ/X6gGTLqa9CmfDq5UDqYFFzuWwN4HJ+ryOuak1CGwS\n" +
            "KJUBSA75HExbv0naWg+suy+pEDvF0VALPU9VUkSQtHyR10YO2FWOe3AEtpbYDRwp\n" +
            "dr1ZwEbb3L6IGQ5i/4CNHbJ2u3yUeXsDNAvrpVSEcIjA01RPCOKmf58SDZp4yDdP\n" +
            "xGhM8w6a18+fdQr22f2cJ0xgfPlbzFbO+FUsEgKvn6QTLhbaYw4zs7rdQDejWHV8\n" +
            "2hP4K+rb9FwknYdV9uo4m77MgGlU+4yvJnGEYaL3jwjI3bH9aooNOl6XbvVAzNzo\n" +
            "mYmaTO7mp6xFAu43yuGyd9K+1E4k7CQTROxTZ+RdtQjV95hSsEmMg792nQvDSBW4\n" +
            "xwfOQ7pf3kC7r9fm8u9nBlEN12HsbQ8Yvux/ld5q5RaIlD19jzfVR6+hJzbj2ZnU\n" +
            "yQs4ksAfIHTzTdLttRxS9lTRTkVx2vbUnoSBy6TYF1mf6nRPpSm1riZxnkR4+BQL\n" +
            "/0rUAxwegTNIG/5M612s2a45QvYK1turZ7spI1RGitJUIjBXUuR76jIsyqagIhBl\n" +
            "5nEsQ4HLv8OQ3EgJ5T9gldLFpHNczLxBQnnNwfPoD2e0kC/iy0rfiNX8HWpTgQpb\n" +
            "zAosLj5/E0iNlildynIhuqBosyRWFqGva0O6qioL90srlzlfKCloe9R9w3HizjCb\n" +
            "f59yEspuJt9iHVNOPOW2Wj5ub0KTiJPp9vBmrFaB79/IlgojpQoYvQ77Hx5A9CJq\n" +
            "paMCHGOW6Uz9euN1ozzETEkIPtL8XAxcogfpe2JKE1uS7ugxsKEGEDfxOQFKAGV0\n" +
            "XFtIx50vFCr2vQro0WB858CGN47dCxChhNUxNtGc11JNEkNv/X7hKtRf/5VCmnaz\n" +
            "GWwNK47cqZ7GJfEBnElD7s/tQvTC5Qp7lg9gEt47TUX0bjzUTCxNvLosuKL9+J1W\n" +
            "ln1myRpff/5ZOAnZTPHR+AbX4bRB4sK5zijQe4139Dn2oRYK+EIYoBAxFxSOzehP\n" +
            "IcKKBB8RCAA8BQJd/gppAwsJCgkQm6eJ3HbWhJoEFQoJCAIWAQIXgAIbAwIeARYh\n" +
            "BHH/2gBECeXdsMPo8Zunidx21oSaAABihQD/VWnF1HbBhP+kLwWsqxuYjEslEsM2\n" +
            "UQPeKGK9an8HZ78BAJPaiL3OpuOmsIoCfOghhMZOKXjIV+Z57LwaMw7FQfPgzSZD\n" +
            "YXJvbCBPbGRzdHlsZSA8Y2Fyb2xAb3BlbnBncC5leGFtcGxlPsKKBBMRCAA8BQJd\n" +
            "/gppAwsJCgkQm6eJ3HbWhJoEFQoJCAIWAQIXgAIbAwIeARYhBHH/2gBECeXdsMPo\n" +
            "8Zunidx21oSaAABQTAD/ZMXAvSbKaMJJpAfwp1C7KAj6K2k2CAz5jwUXyGf1+jUA\n" +
            "/2iAMiX1XcLy3n0L8ytzge8/UAFHafBl4rn4DmUugfhjzsPMBF3+CmgQDADZhdKT\n" +
            "M3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0OJz2vh59nusbBLzgI//Y\n" +
            "1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vhyVeJt0k/NnxvNhMd0587\n" +
            "KXmfpDxrwBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0UjREWs5Jpj/XU9LhEoyXZk\n" +
            "eJC/pes1u6UKoFYn7dFIP49Kkd1kb+1bNfdPYtA0JpcGzYgeMNOvdWJwn43dNhxo\n" +
            "euXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8MTBqvPgWZYx7MNuQx/ejIMZHl+Iaf7hG\n" +
            "976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9+4dq6ybUM65tnozRyyN+\n" +
            "1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpXduVd32MA33UVNH5/KXMV\n" +
            "czVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0SFhlfnBEUj1my1sMAIfl\n" +
            "/H7JQB1nxW7/bNZMfHBYn9fqAZMupr0KZ8OrlQOpgUXO5bA3gcn6vI65qTUIbBIo\n" +
            "lQFIDvkcTFu/SdpaD6y7L6kQO8XRUAs9T1VSRJC0fJHXRg7YVY57cAS2ltgNHCl2\n" +
            "vVnARtvcvogZDmL/gI0dsna7fJR5ewM0C+ulVIRwiMDTVE8I4qZ/nxINmnjIN0/E\n" +
            "aEzzDprXz591CvbZ/ZwnTGB8+VvMVs74VSwSAq+fpBMuFtpjDjOzut1AN6NYdXza\n" +
            "E/gr6tv0XCSdh1X26jibvsyAaVT7jK8mcYRhovePCMjdsf1qig06Xpdu9UDM3OiZ\n" +
            "iZpM7uanrEUC7jfK4bJ30r7UTiTsJBNE7FNn5F21CNX3mFKwSYyDv3adC8NIFbjH\n" +
            "B85Dul/eQLuv1+by72cGUQ3XYextDxi+7H+V3mrlFoiUPX2PN9VHr6EnNuPZmdTJ\n" +
            "CziSwB8gdPNN0u21HFL2VNFORXHa9tSehIHLpNgXWZ/qdE+lKbWuJnGeRHj4FAv+\n" +
            "MQaafW0uHF+N8MDm8UWPvf4Vd0UJ0UpIjRWl2hTV+BHkNfvZlBRhhQIphNiKRe/W\n" +
            "ap0f/lW2Gm2uS0KgByjjNXEzTiwrte2GX65M6F6Lz8N31kt1Iig1xGOuv+6HmxTN\n" +
            "R8gL2K5PdJeJn8PTJWrRS7+BY8Hdkgb+wVpzE5cCvpFiG/P0yqfBdLWxVPlPI7dc\n" +
            "hDkmx4iAhHJX9J/gX/hC6L3AzPNJqNPAKy20wYp/ruTbbwBolW/4ikWij460JrvB\n" +
            "sm6Sp81A3ebaiN9XkJygLOyhGyhMieGulCYz6AahAFcECtPXGTcordV1mJth8yjF\n" +
            "4gZfDQyg0nMW4Yr49yeFXcRMUw1yzN3Q9v2zzqDuFi2lGYTXYmVqLYzM9KbLO2Wx\n" +
            "E/21xnBjLsl09l/FdA/bhdZq3t4/apbFOeQQ/j/AphvzWbsJnhG9Q7+d3VoDlz0g\n" +
            "FiSduCYIAAq8dUOJNjrUTkZsL1pOIjhYjCMi2uiKS6RQkT6nvuumPF/D/VTnUGeZ\n" +
            "wooEGBEIADwFAl3+CmkDCwkKCRCbp4ncdtaEmgQVCgkIAhYBAheAAhsMAh4BFiEE\n" +
            "cf/aAEQJ5d2ww+jxm6eJ3HbWhJoAAEEpAP91hFqmcb2ZqVcaRDMSVmhkEcFIRmpH\n" +
            "vDoQtVn8sArWqwEAi8HwbMhL+YwRItRZDknpC4vFjTHVMd1zMrz/JyeuT9k=\n" +
            "=pa/S\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    private static final String BOB_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String BOB_CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP certificate\n" +
            "\n" +
            "mQGNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAbQhQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+iQHOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGuQGNBF2lnPIBDADW\n" +
            "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI\n" +
            "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+\n" +
            "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO\n" +
            "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT\n" +
            "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh\n" +
            "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6\n" +
            "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U\n" +
            "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A\n" +
            "EQEAAYkBtgQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJ\n" +
            "EPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcS\n" +
            "KhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSx\n" +
            "cVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14i\n" +
            "tcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHV\n" +
            "dTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+w\n" +
            "qMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6Vy\n" +
            "jP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xj\n" +
            "zRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PV\n" +
            "NEJd3XZRzaXZE2aAMQ==\n" +
            "=NXei\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @Test
    public void regressionTest() throws IOException {
        SOPImpl sop = new SOPImpl();
        byte[] msg = "Hello, World!\n".getBytes();
        Ready encryption = sop.encrypt()
                .signWith(CAROL_KEY.getBytes())
                .withCert(BOB_CERT.getBytes())
                .plaintext(msg);
        byte[] ciphertext = encryption.getBytes();

        ByteArrayAndResult<DecryptionResult> decryption = sop.decrypt()
                .withKey(BOB_KEY.getBytes())
                .verifyWithCert(CAROL_CERT.getBytes())
                .ciphertext(ciphertext)
                .toByteArrayAndResult();

        byte[] plaintext = decryption.getBytes();
        assertArrayEquals(msg, plaintext);
        assertEquals(1, decryption.getResult().getVerifications().size());
    }
}
