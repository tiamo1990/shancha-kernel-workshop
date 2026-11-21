package com.shancha.ownctl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/** 无线调试端口的连通性探测（配对握手在后续版本接入）。 */
final class AdbPair {
    private AdbPair() { }

    static boolean reachable(String host, int port) {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), 1500);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            try { s.close(); } catch (IOException ignored) { }
        }
    }
}