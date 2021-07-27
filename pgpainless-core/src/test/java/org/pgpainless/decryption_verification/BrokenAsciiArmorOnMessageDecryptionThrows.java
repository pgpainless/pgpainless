/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.StreamUtil;

public class BrokenAsciiArmorOnMessageDecryptionThrows {

    String ASCII_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: FlowCrypt 6.9.1 Gmail Encryption\n" +
            "Comment: Seamlessly send and receive encrypted email\n" +
            "\n" +
            "xcaGBFn7qV4BEACgKfufG6yseRP9jKXZ1zrM5sQtkGWiKLks1799m0KwIYuA\n" +
            "QyYvw6cIWbM2dcuBNOzYHsLqluqoXaCDbUpK8wI/xnH/9ZHDyomk0ASdyI0K\n" +
            "Ogn2DrXFySuRlglPmnMQF7vhpnXeflqp9bxQ9m4yiHMS+FQazMvf/zcrAKKg\n" +
            "hPxcYXC1BJfSub5tj1rY24ARpK91fWOQO6gAFUvpeSiNiKb7C4lmWuLg64UL\n" +
            "jLTLXO9P/2Vs2BBHOACs6u0pmDnFtDnFleGLC5jrL6VvQDp3ekEvcqcfC5MV\n" +
            "R0N6uVTesRc5hlBtwhbGg4HuI5cFLL+jkRwWcVSluJS9MMtug2eU7FAWIzOC\n" +
            "xWa+Lfb8cHpEg6cidGSxSe49vgKKrysv5PdVfOuXhL63i4TEnKFspOYB8qXy\n" +
            "5n3FkYF/5CpYN/HQaoCCxDIXLGp33u03OItadAtQU+qACaGmRhQA9qwe4i+k\n" +
            "LWL3oxoSwQ/aewb3fVo+K7ygGNltk6poHPcL0dU6VHYe8h2MCEO/1LR7yVsK\n" +
            "W47B4fgd3huXh868AX3YQn4Pd6mqft4WdcCuRpGJgvJNHq18JvIysDpgsLSq\n" +
            "QF44Z0GOH2vQrnOhJxIWNUKN+QnMy8RN6SZ1UFo4P+vf1z97YI2MfrMLfHB/\n" +
            "TUnsxS6fGrKhNVxN7ETH69p2rI6F836EZhebLQARAQAB/gkDCDyuMzkoMQjC\n" +
            "YLUdlPhViioPQAb/WMfaiE5ntf3u2Scm1mGuXTQsTmU2yTbY3igXTJ6YJH4C\n" +
            "FLB18f6u+NhZb0r97LteF4JiuTtm6ZA63ejSgp/5Lns1Z5wY7pMNPsH0cTU3\n" +
            "UrFQh/ghoxanSHaN1XQpaovYsOHfsWcYzAxtvqhDV2vqfIlhiL6EdE7Vn84C\n" +
            "QE096Gu4iMtKZSXCDU9B1XN2+rK2e+9c1nQHAXjAq49v9WUzstzjvrCmBajU\n" +
            "GS6Ccy3VHRel458boMNOZqvLOBCtw4nx2GFDs16ZQNZFywj1pThExKMxHlnB\n" +
            "Sw6tMJ0FJBCk2E9S28Buudu6sJJerZGjUKIafoSCcO8wpvixzL1s4dqJs+iH\n" +
            "Rv04xfHk78rgaP010NwoqHjd+ops+NxLoC9dS5PcDm9CAuBxRjf9gSJ8Qo8w\n" +
            "1jeldj93qiYU4Z0O87rzW+IDX6GBIcE8JghpOO+XMxN0nfb2EZpkFhBLe62j\n" +
            "JOgQsdoYy+iBKGSgx2uoHIvifxiq827XGCXTZmHkAwZyJPl7myja/qdiudlD\n" +
            "FnBtOexTnZ77HXlFC9s7/PItZZqKnIPuIKhsW/Tk8fzpUPf7Uu0tS/vCzc8+\n" +
            "abrpQM2ppI7O93kCKJdXVzKioE2MfV5DhLjNOe82ORWZO4uwCg2u8ZHhCOzz\n" +
            "MsMpAm89f+1nvOQtvBS9v45MhZdbndwPHQEg2pM689ZxHw9EgPiOhyOMFGM1\n" +
            "4tBZ3jYfPxGxTW7NZfryWUQxvSSkFaLsPMjxTB93T/fsJdeUDGKJR44cRweP\n" +
            "ATQWK/EBgx1d+jJUHKYl5aHUxdKLvwH1ikzgHuKkb4pV0yaRjONy8sEgXYkj\n" +
            "HoH1qfZAqbCoqraRorTEgO9QvzaLKb9gdDjEMxuzEJuA3QxP9HqHR5aU+T8o\n" +
            "hXss9SMFVjVok6t92v6keeUVRJYxjhoROZNUeMwfIg/EQEXACQUIGokJqaYC\n" +
            "4TX3GoLWa5+BTw5ChKiRC9VOyFNvq8Q2euBzSRoYPYUU7ekDawUQU+SCpN0I\n" +
            "3HYiJlGzDJ7zwFybeEMdv1F94F4NefROdRFcPtzrAJ4LM38zoq2YEUyK9RN0\n" +
            "lO2I9BFw30AR+Ps/qxtptWtzNXBohYuNNpaZt2UMcMOZhRYmHJjq59oH65X9\n" +
            "/l8wEk4nxgFmCjnpHyGpn2jtdMtRDrwAeHKBJ4ZQUV3SU/cgpc0VZ2rg+ZqL\n" +
            "7iAWfofoD/M/3bEOu6ePqcl2bKOhw8RT07CimovKUcXujp7/hsj47yNGKASs\n" +
            "rZMyJXT+VqMA/MWb++jOUwQkCz6dlzM8W5UC2ezlm1uIX+nrZp0LoWzq2VGG\n" +
            "ENbDpnyXh0W3FmVeSgwej1Fg7AJ4wdLkPxeb916UGONrUbFYRtE7jAo/h9c3\n" +
            "kus/8rsxMVfTvQu+tZPO7liWxhuuRWaG+YOJe2s8NYuqlyyPpvKRtGIqy363\n" +
            "c9j5VnfqOil1SxAjEgm7E5AHkCdQD2/BL4+hReex27WejedSHRVyQ6M8H0RO\n" +
            "+48eflFeaCTTWE970HIZ1hMQTf3bLEaB08758UuYVa7geF6jQmpg8OnkRPBQ\n" +
            "acQHgBOV1Fzf0an0uMhVw0vBQIX3XdaLe+uVUuvl00VOLB4JErCQzKDGsAMj\n" +
            "N2uE1cACfAEauTMik9+/G5wp2hW8JOO1mrH7lq7z3RzhJN/VkTFFSOGy/mB1\n" +
            "yu4inb+u5aVyJIL5ljs/NBno9b/aDOUmmiHw4my0KCQVdGNbletqfjeJV4gM\n" +
            "IQnXYXlQgg398LBawCNLYHkb/dDNO0Zsb3dDcnlwdCBDb21wYXRpYmlsaXR5\n" +
            "IDxmbG93Y3J5cHQuY29tcGF0aWJpbGl0eUBnbWFpbC5jb20+wsF/BBABCAAp\n" +
            "BQJZ+6ljBgsJBwgDAgkQrawnnJUJMgcEFQgKAgMWAgECGQECGwMCHgEACgkQ\n" +
            "rawnnJUJMgfO5g//audO5E7KXiXIQzqsVfh0RpOS5KwDa8ZNAOzbBjQbfjyv\n" +
            "jnvej9pYy+7Pot9NDfGtMEMpWj5uWuPhD1fv2Kv/uBP4csJqf8Vbs1H1hD4s\n" +
            "D21RrHerM7xCFzIN1XHhkemR7IALNfekrC9TGi4IYYZrZKz/yK0lCjT8BIro\n" +
            "jYUE5CODa8mKPB2BSmJwqNwZxhr0KKnPykrOAZfpArnHEdY3JE54Se6FCxKM\n" +
            "WOtnKBHcwHiSTsX/nBtK30sCul9j1Wgd1jFRJ244ESJd7M6cBlNrJ6GTZDil\n" +
            "rmpo9nVO0slTwD/YD6GCyN3r3hJ3IEDnwZK05pL+1trM6718pyWaywfT62vW\n" +
            "zL7pNqk7tIghX+HrvrHVNYs/G3LnN9m5zlCJMk5wKP+f9olsz3Llupam2auk\n" +
            "g/h1HXEl3lli9u9QkJkbGaEDWR9UCnH/xoybpS0mgjVYt0B6jNYvHBLLhuaj\n" +
            "hR+1sjVIIg0kwfxZfQgFXyAL8LWu4nNaSEICUl8hVBWf9V6Xn4VX7JkkWlE3\n" +
            "JEByYiuZkADhSdyklJYkR9fQjUc5AcZsUgOuTXsY4fG0IEryMzrxRw0qgqG1\n" +
            "7rir1uqrvLDrDM18FPWkW2JwGzF0YR5yezvvz3H3rXog+ryEzeZAN48Zwrzv\n" +
            "GRcvEZJFmB1CwTHrW4UykC592pqHR5K4nV7BUTzHxoYEWfupXgEQAK/GGjyh\n" +
            "3CHg0yGZL5q4LJfn2xABV00RXiwxNyPc/7YzYgSanBQmzFj3AMJhcFdJx/Eg\n" +
            "3i0pTr6qbAnwzkYoSm9R9k40PTA9LP4AMBP4uXiwbbkV2Nlo/RMgmHN4Kquz\n" +
            "wY/hbNK6ZujFtDGXp2s/wqtfrfmdDnXuUhnilrOo6NR/DrtMaEmsXTCfQiZj\n" +
            "nmSkAEJvVUJKihb9C51LzFSWPYEMkjOWo03ZSYJR6NjubjMK2hVEbh8wQ7Wv\n" +
            "vdfssOiwO+gwXw7zibZphCMA7ADVqUeM10q+j+TLGh/gvpm0ghqjKZsdk2eh\n" +
            "ncUlTQhDkwY8JJ5iJ6QThgjYwaAcC0Ake5rA/7nPn6YMnxlP/R7Nq651l8SB\n" +
            "ozcTzjseOSwearH5tMeKyastTWEIHFAd5rYIEqawpx9F87kLxRhQj9NUQ6uk\n" +
            "mdR66P8elsm9AZdQuaQF53oEQ5zwuUK8+wXqDTC853XtfHsCvxKENP0ZXXvy\n" +
            "qVo2INRNBO5WlSYQjGxoxohs1X+CMAmFSDvbV70dZVf0cQJ9GidocAv70DOH\n" +
            "eXBuOiXZBqyGSNjecPl2bFr4A6r5RMnNZDrYieXJOEWUqgaX0uNQacX4Aecm\n" +
            "KiCEyR08XKEPVnnJGUM7mOvhuGdH0ZC03ZUPqLAhfW2cxcsiOeTQ7tc8LLaT\n" +
            "u348PxVsPkN19RbBABEBAAH+CQMIXnc7lrdca0Rg8eLOHqbZ4HZeKswdL0Jg\n" +
            "lNZ9Fnp2ZPOgrnYxqeCbpRoZwr09aZ/DYiUfUgDuuJIRFzmorhczyKMOWTW+\n" +
            "eTTGFWIJB4ANAGie4EUhrJe4cDFxPg4Uvuvk/KMt5kLTOcSaN70kIKvt2lQT\n" +
            "LFzi6gCW9TWAtf5Jg+CcOoOw0tIsBcxTSL2V6SQDAS9KBJcgyhQAvbey44Zb\n" +
            "8s8kmtt1Xwl9bEtG2uDvKNvbb1GszeXf1wW2acwO4OAmrJXMhOscWb6eiDx+\n" +
            "9sIM5VoDrUG6K+72VSn9xqbEE9K5+U83qeAIb8dn+FLuKR0+auAJF19bkCUz\n" +
            "ZQS3wXzCm/D+PqE+BWexd7Jd8m/zg0eSzw+0hAxQ7sw5c2EdZ6LmqA1qs6yU\n" +
            "gIk92HufgO+fpRnUVRhD7ZklxfaG3dLIdbOs5R6DdA9z015r2VOh4S5mLJfY\n" +
            "rCQqEtqbtJpUOreyXejDYOCvv/mpFa81EWOMGmySvEPK7d25VAgIM/MS2l2H\n" +
            "+oJ7nMI4ZxgB7W4nVz15YK3RoJKAlcyy//1MAyNbH3TU8rytOKcPfCB7qgAP\n" +
            "6yjBGrej0IzuMWBmuuLCvfiYIqYDBgZ6GruAJhuudPXbhojl0l9z+lcM94IU\n" +
            "GOoGGhUIy3Zgt2nLQFB4vegY2EYUBMOO6dYeMh2QMwlSU63cnpxE/w6wby8b\n" +
            "RZ4GDPEBmYkCTZ0vbV34vJ72Z+LJ0/FOrTuQA8RHUJ7LMkTV5OF8oo20cE9O\n" +
            "h8Eyay+yYtccL2M8mpiJ9FXOyxURVyz4VaDfSXfo2auSzvUALVA/kMT3IVWZ\n" +
            "929TCb5uI/KwcqIMlP5Ih5hj0+0C34v5XnkNDLO8G3bcQ+NAb3ydUg5FpERy\n" +
            "0vW5TtgQmf04CdPJ341urINodtrUSabiOqBHSTLVaaYbSFcGF7Ur4lRwDlx3\n" +
            "50JqAcbp8Dl2eKMjW7EkHnTaKKC7lJwG62I3XbVg4mdkgzNAOF9UKjdHVn7Q\n" +
            "/DU3m67ZN5wwSruffu6DWNrDnytpl9Hdw2s9AF5UN1WfxobO7OD2vQPJ8Fcg\n" +
            "8kPUgnJ1OzBtvzNP53Aorbd8RDxx7rBQBtCFQN8Uq1ksUKiYNqbeRZ6vOtmH\n" +
            "LhiyhjMsrF0cog7r86dAAlWQJLnv+zUtdZ2LGS3aGMjAb7Y/iOVS5Q6/7Zw9\n" +
            "3wKAAfl7vFdZ7TFzq/p1/+xwc42WtO96XjFCtqKtpQ4sGRMUt7zUuq8ZJk26\n" +
            "ja94/v6iHhR9GID3HNiDLRvpQPFiK5PM5p6EI0Z5JfL5OQjvsmv/ltu5XmO6\n" +
            "08uXoZJM7IwPBdGZ7yNrDu0E9MEU7UW5kgSQzeGESV+jw2rXxU6wXeIAhkGh\n" +
            "um7f0JoKqYYOjRDLAXOtJgVAHGcto+U4XJQK4Bv7ohCpP0M+hSrEU1uYGC1G\n" +
            "4O6GSpN+4WV99i+JLFBya0R0ZUZfKQuU0EjRXX39WKT5LX7cUTTMHtuY3Xd/\n" +
            "BC/YMFqbk5+MZ0P1L1awJGkhMSc1qCrQ1OEtMk49ak2IrT+E19gQ6lR3q7yQ\n" +
            "B5D7ys/Z5X0ZbTsy6GK5JZE3X31of/DTbigqWLENk3oh5OaDNZ1hYUmHe03s\n" +
            "QuVrwD8TWqig4/KfQgFrUDLEdTZJezUsybHzjzWw5E8+5WrlBnx5PERaZzBF\n" +
            "wubVzAIAD9NsRGAzEF0ZBIsqzcxMQzF0jnvtl7YENQuH9ZYNuZY9h9f8uczV\n" +
            "6WM2HmQioFUswnzC+FNwC9Re+NNjrtdQAsVJAnn2BW4tvXlYb37foe0r8WDk\n" +
            "ULZ4Q8LBaQQYAQgAEwUCWfupZAkQrawnnJUJMgcCGwwACgkQrawnnJUJMge5\n" +
            "uA/+NA4zV+NWRNIpkyTDPD7FGi4pmFcMUs96Wzcedx244au4ixLLprSOib5e\n" +
            "A1UImjRWptJII6rZJCHVrB/rFJVQhSHaJQCsSd8K0N1DOOrv4oaGrL9zyzPd\n" +
            "ATW8izY9rzIRaNg9Si8DvULfKIheLI429RWDfeYFjFPVJ8n55gwaf28Nptxs\n" +
            "yo4mEWhf+pF/l8HaQtOzLB82PE4NXwrzf2MogNz3W5BMvcWZo1Vma4Iz1IJf\n" +
            "HdNlZYJO1vMC7u/7JYAztyH50mXT9Jh6U2jim5OElFRNEUh35E1L2G6XzRdO\n" +
            "JrEXbghF7EO+iekIyRScf2pE+vNBhL2iwnJs+ChgFDFIGnR+Zjwl3rG8mux0\n" +
            "iykse5vOToid8SEZ16nu7WF9b8hIxOrM7NBAIaWVD9oqsw8u+n30Mp0DB+pc\n" +
            "0Mnhy0xjMWdTmLcp+Ur5R2uZ6QCZ0lYzLFYs7ZW4X6mT3TwtGWa7eBNIRiyA\n" +
            "Bm5g3jhTi8swQXhv8MtG6eLix8H5/XDOZS91y6PlUdAjfDS34/IeMlS8SM1Q\n" +
            "IlBkLHqJ18viQNHqw9iYbf557NA6BVqo3A2OVPyyCVaKRoYH3LTcSEpxMciq\n" +
            "OHsqtYlSo7dRyJOEUQ6bWERIAH5vC95fBLgdqted+a5Kq/7hx8sfrYdL1lJy\n" +
            "tiL0VgGWS0GVL1cZMUwhvvu8bxI=\n" +
            "=2z30\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    Passphrase passphrase = Passphrase.fromPassword("flowcrypt compatibility tests");

    @Test
    public void testInvalidArmorCRCThrowsOnClose() throws PGPException, IOException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: FlowCrypt 5.0.4 Gmail Encryption flowcrypt.com\n" +
                "Comment: Seamlessly send, receive and search encrypted email\n" +
                "\n" +
                "wcFMA+ADv/5v4RgKAQ/+K2rrAqhjMe9FLCfklI9Y30Woktg0Q/xe71EVw6WO\n" +
                "tVD/VK+xv4CHzi+HojtE0U2F+vqoPSO0q5TN9giKPMTiK25PnCzfd7Q+zXiF\n" +
                "j+5RSHTVJxC62qLHhtKsAQtC4asub8cQIFXbZz3Ns4+7jKtSWPcRqhKTurWv\n" +
                "XVH0YAFJDsFYo26r2V9c+Ie0uoQPx8graEGpKO9GtoQjXMKK32oApuBSSlmS\n" +
                "Q+nxyxMx1V+gxP4qgGBCxqkBFRYB/Ve6ygNHL1KxxCVTEw9pgnxJscn89Iio\n" +
                "dO6qZ9EgIV0PVQN0Yw033MTgAhCHunlE/qXvDxib4tdihoNsLN0q5kdOeiMW\n" +
                "+ntm3kphjMpQ6TMCUGtdS7UmvnadZ+dh5s785M8S9oY64mQd6QuYA2iy1IQv\n" +
                "q3zpW4/ba2gqL36qCCw/OaruXpQ4NeBr3hMaJQjWgeSuMsQnNGYUn5Nn1+9X\n" +
                "wtlithO8eLi3M1dg19dpDky8CacWfGgHD7SNsZ2zqFqyd1qtdFcit5ynQUHS\n" +
                "IiJKeUknGv1dQAnPPJ1FdXyyqC/VDBZG6CNdnxjonmQDRh1YlqNwSnmrR/Sy\n" +
                "X7n+nGra+/0EHJW6ohaSdep2jAwJDelq/DI1lqiN16ZXJ2/WH6pItA9tmkLU\n" +
                "61QUz6qwPAnd0t6iy/YkOi2/s1+dwC0DwOcZoUPF8bTBwUwDS1ov/OYtlQEB\n" +
                "D/46rCPRZrX34ipseTkZxtw3YPhbNkNHo95Mzh9lpeaaZIqtUg2yiFUnhwLi\n" +
                "tYwyBCkXCb92l1GXXxGSmvSLDSKfQfIpZ0rV5j50MYKIpjSeJZyH/3qP+JXv\n" +
                "Z47GsTp0z5/oNau5XQwuhLhUtRoZd1WS9ahSJ1akiKeYJroLbTg10fjL25yp\n" +
                "iaoV16SqKA1H/JOuj6lT5z1nuez35JjeSpUc7ksdot60ZovMfWC+OGRnkYKb\n" +
                "7KxFd7uaxL6uOBOFyvRxYeohKd73aVkiKpcWd4orI18FhlftFNAwIdsmfzNc\n" +
                "mzTHZaUl89iYxEKR6ae6AKws1wzLq0noarsf2eKBVbTSfmK3S3xFqduKINnc\n" +
                "e5Yb3F5adSj1dUjm1BZ4aqzsgKyBb+J8keG9ESsnFOyxOIUXDM1nIo1IOgzC\n" +
                "M928Jb9GVa+uhdXRrb5cLjTihTusJN0I8oJrwKkwIpCJVgPMdDLkeubrMBQ4\n" +
                "fbpl4V76sOU2Nx+6nG2FnFBFBFohOL+0nTK5/6Ns9ateN7K9VP++QcoeqfPk\n" +
                "IUO3+lCZW+trTSvvFId3ziUVsPTeuAS+7nxSMfWZ/K9Ci6QV/Xnx3F/qSmuS\n" +
                "AUm4zPQ1EjZf1N/5K+vhcCTN4MMx406VlqtedkXL2KPwZ6jDS/ww8RfcmPnD\n" +
                "s94ct0WCZZtNlnQq+5h0ybwTJNLC2QFyrhhPqztVY95n9La2Mw5WITCWzg/d\n" +
                "IBUceW/OwHYtePyaSQkCnegDw/2mN2/GC8d0OlwULcTYG6uVenGv2UOUbCr3\n" +
                "Pfy/Eb/VqUEZK00PdvVQV7FWYAshuTFPTqidph04CgQvBpi3SDEEo8SkEIFS\n" +
                "/iEeRQaWjFEXKUI3FwKXPJQWvFpbrXBOAjnxXXbAFYOLxdydmq1GVl9Mm3GU\n" +
                "Clc9g6t9vaYDBPx2gN562/CM/nT8Vq45VHe79XkrrcHDwLn7yeHJScNFsib+\n" +
                "VvwTPoUftlhC/ai21D403TsJpm7ZmPcDjagoIcXrS/lN03z79RBmSKFtYiXW\n" +
                "4obkKSGow61vMBh2/XLVYKJKpYKm/GnVlJxA0zQVl558x8I/nAMaxSzwx+ZY\n" +
                "waVU/s5PLZ7Ghg3MOguiRTlflKUQyL0A7NR46OjFgUnHAZRxr4KO3GoxVPy4\n" +
                "XLeS4+Wl68s7QlV6WF1IKCHWEUMEeRRea2/OvvlS/oLs2MNNWDemlJ4SiXHf\n" +
                "xINU38Txo84A00NALbKppsSyy9Gwj//rO/FcerupkfeuOm9nHFwIQeeC5bWD\n" +
                "mmRlC90r2jY8gM/v3Jjy9h8PbXWxh9MUpc7/kAcTwdGlMxiVjE29p065qTRr\n" +
                "Oi6sJ7pWuYTfWldZqTVmaBjlv0zuXQ8Eo8o/USvoTs+oihYIMcqReqdeqr/N\n" +
                "e+sDtYKRg/LKp/JJ5nAQzVMP67DxkgwLNxx0ijBLysaQmvRlsiYWayxZB1Xd\n" +
                "BxA2bjZRvsmww+hgSKNlcsiubJGBqfqvgmlebZuJHHSC1L6mdMYgcihKmYAj\n" +
                "p+HFLyqgyeRVMdjRHcrEdxNPG4fJmlk1bYiVQQ4XAd72w+AHS/seZ5HzbAK0\n" +
                "omuHYUD5PTEqZ1K9JObSsh3XMUkJK+z3BnrOxnTOOyG2r+4FxizH6rfz/Pgg\n" +
                "sPxqxE9ELUlgQe8plcPFge6aN9tUoSe+vMtDaEAqKw9JwofBF7jlxTqMMvQC\n" +
                "gWbn9x3W5o4VrnpjYGtPl8sh1QREu0A+0PUJAKL4A3GSMYRouGewLSMNJlOg\n" +
                "/0pPF6qB+Fi4GJ7ju5C07tfr9z9UqRj09kDXJuoJd95NdSiCz6ndugn6gs8B\n" +
                "Qf/XPxZVefeMLiB6p8pG0iZ/jcJjyYJLtTg6kA+1/ffmJPfH/76ZA9dgEJLj\n" +
                "/W2u0Lp4NY8cwqcXuGKgl72TVJ34Iawl35Y0yr47k/7Y1vEQ5Q3bT7HP5A==\n" +
                "=FdCC\n" +
                "-----END PGP MESSAGE-----\n";

        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(ASCII_KEY);
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions().addDecryptionKey(
                        key, SecretKeyRingProtector.unlockAllKeysWith(passphrase, key)
                ));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        StreamUtil.pipeAll(decryptionStream, outputStream);
        assertThrows(IOException.class, decryptionStream::close);
    }
}
