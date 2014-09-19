package com.yossis.net;

import java.net.UnknownHostException;

/**
 * Created by freds on 9/19/14.
 */
public class Log {
    public static void debug(String msg) {
        System.out.println("Debug: "+msg);
    }

    public static void info(String msg) {
        System.out.println("Info: "+msg);
    }

    public static void warn(String msg) {
        System.out.println("Warn: "+msg);
    }

    public static void error(String msg, Throwable throwable) {
        System.err.println("ERROR: "+msg);
        throwable.printStackTrace();
    }
}
