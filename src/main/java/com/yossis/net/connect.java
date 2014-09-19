package com.yossis.net;

import java.io.IOException;
import java.net.URL;

/**
 * @author Yossi Shaul
 */
public class connect {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: connect DESTINATION_URL");
            System.exit(1);
        }

        new URL(args[0]).openConnection().connect();
        System.out.println("Successfully connected to: " + args[0]);
    }

}
