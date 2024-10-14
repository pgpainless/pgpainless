// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm

enum class OpenPgpPacket(val tag: Int) {
    PKESK(1),
    SIG(2),
    SKESK(3),
    OPS(4),
    SK(5),
    PK(6),
    SSK(7),
    COMP(8),
    SED(9),
    MARKER(10),
    LIT(11),
    TRUST(12),
    UID(13),
    PSK(14),
    UATTR(17),
    SEIPD(18),
    MDC(19),
    OED(20),
    PADDING(21),
    EXP_1(60),
    EXP_2(61),
    EXP_3(62),
    EXP_4(63),
    ;

    companion object {
        @JvmStatic
        fun fromTag(tag: Int): OpenPgpPacket? {
            return values().firstOrNull { it.tag == tag }
        }

        @JvmStatic
        fun requireFromTag(tag: Int): OpenPgpPacket {
            return fromTag(tag)
                ?: throw NoSuchElementException("No OpenPGP packet known for tag $tag")
        }
    }
}
