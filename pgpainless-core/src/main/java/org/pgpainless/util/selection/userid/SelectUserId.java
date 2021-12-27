// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.userid;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.pgpainless.PGPainless;

import javax.annotation.Nonnull;

public abstract class SelectUserId {

    protected abstract boolean accept(String userId);

    public List<String> selectUserIds(PGPKeyRing keyRing) {
        List<String> userIds = PGPainless.inspectKeyRing(keyRing).getValidUserIds();
        return selectUserIds(userIds);
    }

    public List<String> selectUserIds(List<String> userIds) {
        List<String> selected = new ArrayList<>();
        for (String userId : userIds) {
            if (accept(userId)) {
                selected.add(userId);
            }
        }
        return selected;
    }

    public String firstMatch(PGPKeyRing keyRing) {
        return firstMatch(selectUserIds(keyRing));
    }

    public String firstMatch(List<String> userIds) {
        for (String userId : userIds) {
            if (accept(userId)) {
                return userId;
            }
        }
        return null;
    }

    public static SelectUserId containsSubstring(@Nonnull CharSequence query) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.contains(query.toString());
            }
        };
    }

    public static SelectUserId exactMatch(@Nonnull CharSequence query) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.equals(query.toString());
            }
        };
    }

    public static SelectUserId startsWith(@Nonnull CharSequence substring) {
        String string = substring.toString();
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.startsWith(string);
            }
        };
    }

    public static SelectUserId containsEmailAddress(@Nonnull CharSequence email) {
        String string = email.toString();
        return containsSubstring(string.matches("^<.+>$") ? string : '<' + string + '>');
    }

    public static SelectUserId validUserId(PGPKeyRing keyRing) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return PGPainless.inspectKeyRing(keyRing).isUserIdValid(userId);
            }
        };
    }

    public static SelectUserId and(SelectUserId... strategies) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                boolean accept = true;
                for (SelectUserId strategy : strategies) {
                    accept &= strategy.accept(userId);
                }
                return accept;
            }
        };
    }

    public static SelectUserId or(SelectUserId... strategies) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                boolean accept = false;
                for (SelectUserId strategy : strategies) {
                    accept |= strategy.accept(userId);
                }
                return accept;
            }
        };
    }

    public static SelectUserId not(SelectUserId strategy) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return !strategy.accept(userId);
            }
        };
    }

    public static SelectUserId byEmail(CharSequence email) {
        return SelectUserId.or(
                SelectUserId.exactMatch(email),
                SelectUserId.containsEmailAddress(email)
        );
    }
}
