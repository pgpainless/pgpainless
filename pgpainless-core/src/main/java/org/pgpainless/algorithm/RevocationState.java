// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.algorithm;

import org.pgpainless.util.DateUtil;

import javax.annotation.Nonnull;
import java.util.Date;
import java.util.NoSuchElementException;

public final class RevocationState implements Comparable<RevocationState> {

    private final RevocationStateType type;
    private final Date date;

    private RevocationState(RevocationStateType type) {
        this(type, null);
    }

    private RevocationState(RevocationStateType type, Date date) {
        this.type = type;
        if (type == RevocationStateType.softRevoked && date == null) {
            throw new NullPointerException("If type is 'softRevoked' then date cannot be null.");
        }
        this.date = date;
    }

    public static RevocationState notRevoked() {
        return new RevocationState(RevocationStateType.notRevoked);
    }

    public static RevocationState softRevoked(@Nonnull Date date) {
        return new RevocationState(RevocationStateType.softRevoked, date);
    }

    public static RevocationState hardRevoked() {
        return new RevocationState(RevocationStateType.hardRevoked);
    }

    public RevocationStateType getType() {
        return type;
    }

    public @Nonnull Date getDate() {
        if (!isSoftRevocation()) {
            throw new NoSuchElementException("RevocationStateType is not equal to 'softRevoked'. Cannot extract date.");
        }
        return date;
    }

    public boolean isHardRevocation() {
        return getType() == RevocationStateType.hardRevoked;
    }

    public boolean isSoftRevocation() {
        return getType() == RevocationStateType.softRevoked;
    }

    public boolean isNotRevoked() {
        return getType() == RevocationStateType.notRevoked;
    }

    @Override
    public String toString() {
        String out = getType().toString();
        if (isSoftRevocation()) {
            out = out + " (" + DateUtil.formatUTCDate(date) + ")";
        }
        return out;
    }

    @Override
    public int compareTo(@Nonnull RevocationState o) {
        switch (getType()) {
            case notRevoked:
                if (o.isNotRevoked()) {
                    return 0;
                } else {
                    return -1;
                }

            case softRevoked:
                if (o.isNotRevoked()) {
                    return 1;
                } else if (o.isSoftRevocation()) {
                    // Compare soft dates in reverse
                    return o.getDate().compareTo(getDate());
                } else {
                    return -1;
                }

            case hardRevoked:
                if (o.isHardRevocation()) {
                    return 0;
                } else {
                    return 1;
                }

            default:
                throw new AssertionError("Unknown type: " + type);
        }
    }

    @Override
    public int hashCode() {
        return type.hashCode() * 31 + (isSoftRevocation() ? getDate().hashCode() : 0);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RevocationState)) {
            return false;
        }
        RevocationState other = (RevocationState) obj;
        if (getType() != other.getType()) {
            return false;
        }
        if (isSoftRevocation()) {
            return DateUtil.toSecondsPrecision(getDate()).getTime() == DateUtil.toSecondsPrecision(other.getDate()).getTime();
        }
        return true;
    }
}
