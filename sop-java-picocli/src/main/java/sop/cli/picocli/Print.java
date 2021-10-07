// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

public class Print {

    public static void errln(String string) {
        // CHECKSTYLE:OFF
        System.err.println(string);
        // CHECKSTYLE:ON
    }

    public static void trace(Throwable e) {
        // CHECKSTYLE:OFF
        e.printStackTrace();
        // CHECKSTYLE:ON
    }

    public static void outln(String string) {
        // CHECKSTYLE:OFF
        System.out.println(string);
        // CHECKSTYLE:ON
    }
}
