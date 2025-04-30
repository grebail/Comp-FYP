package com.example.libraryapp;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import fi.iki.elonen.NanoHTTPD;

public class AssetServer extends NanoHTTPD {
    private Context context;

    public AssetServer(Context context, int port) {
        super(port);
        this.context = context;
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        if (uri.equals("/")) {
            uri = "/login.html"; // Default to login.html when root is accessed
        }
        try {
            InputStream is = context.getAssets().open("www" + uri);
            String mimeType = getMimeType(uri);
            long size = is.available();
            return newFixedLengthResponse(Response.Status.OK, mimeType, is, size);
        } catch (IOException e) {
            return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "File not found");
        }
    }

    private String getMimeType(String uri) {
        if (uri.endsWith(".html")) {
            return "text/html";
        } else if (uri.endsWith(".css")) {
            return "text/css";
        } else if (uri.endsWith(".js")) {
            return "application/javascript";
        } else if (uri.endsWith(".png")) {
            return "image/png";
        } else if (uri.endsWith(".jpg") || uri.endsWith(".jpeg")) {
            return "image/jpeg";
        } else {
            return MIME_PLAINTEXT;
        }
    }
}