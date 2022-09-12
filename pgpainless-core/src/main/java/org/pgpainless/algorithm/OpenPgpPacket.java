// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.bouncycastle.bcpg.PacketTags;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

public enum OpenPgpPacket {
    PKESK(PacketTags.PUBLIC_KEY_ENC_SESSION),
    SIG(PacketTags.SIGNATURE),
    SKESK(PacketTags.SYMMETRIC_KEY_ENC_SESSION),
    OPS(PacketTags.ONE_PASS_SIGNATURE),
    SK(PacketTags.SECRET_KEY),
    PK(PacketTags.PUBLIC_KEY),
    SSK(PacketTags.SECRET_SUBKEY),
    COMP(PacketTags.COMPRESSED_DATA),
    SED(PacketTags.SYMMETRIC_KEY_ENC),
    MARKER(PacketTags.MARKER),
    LIT(PacketTags.LITERAL_DATA),
    TRUST(PacketTags.TRUST),
    UID(PacketTags.USER_ID),
    PSK(PacketTags.PUBLIC_SUBKEY),
    UATTR(PacketTags.USER_ATTRIBUTE),
    SEIPD(PacketTags.SYM_ENC_INTEGRITY_PRO),
    MOD(PacketTags.MOD_DETECTION_CODE),

    EXP_1(PacketTags.EXPERIMENTAL_1),
    EXP_2(PacketTags.EXPERIMENTAL_2),
    EXP_3(PacketTags.EXPERIMENTAL_3),
    EXP_4(PacketTags.EXPERIMENTAL_4),
    ;

    static final Map<Integer, OpenPgpPacket> MAP = new HashMap<>();

    static {
        for (OpenPgpPacket p : OpenPgpPacket.values()) {
            MAP.put(p.getTag(), p);
        }
    }

    final int tag;

    @Nullable
    public static OpenPgpPacket fromTag(int tag) {
        return MAP.get(tag);
    }

    @Nonnull
    public static OpenPgpPacket requireFromTag(int tag) {
        OpenPgpPacket p = fromTag(tag);
        if (p == null) {
            throw new NoSuchElementException("No OpenPGP packet known for tag " + tag);
        }
        return p;
    }

    OpenPgpPacket(int tag) {
        this.tag = tag;
    }

    int getTag() {
        return tag;
    }
}
