package com.example.libraryapp;

import android.content.Context;
import java.io.IOException;

public class ServerManager {
    private static AssetServer server = null;

    public static void startServer(Context context) {
        if (server == null) {
            try {
                // Use application context to avoid tying the server to an activity lifecycle
                server = new AssetServer(context.getApplicationContext(), 8080);
                server.start();
            } catch (IOException e) {
                // Log the error or handle it as needed
                e.printStackTrace();
            }
        }
    }

    public static void stopServer() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }

    public static boolean isServerRunning() {
        return server != null;
    }
}