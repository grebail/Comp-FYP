package com.example.libraryapp;

import android.os.Bundle;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class BookLocationActivity extends AppCompatActivity {
    WebView webApp;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_book_location);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        // Start the shared AssetServer
        ServerManager.startServer(this);
        if (!ServerManager.isServerRunning()) {
            Toast.makeText(this, "Failed to start server", Toast.LENGTH_SHORT).show();
        }

        webApp = findViewById(R.id.webApp);
        webApp.getSettings().setJavaScriptEnabled(true);
        webApp.getSettings().setCacheMode(WebSettings.LOAD_DEFAULT);
        webApp.clearCache(true);
        webApp.getSettings().setDomStorageEnabled(true);
        webApp.getSettings().setLoadWithOverviewMode(true);
        webApp.getSettings().setUseWideViewPort(true);
        webApp.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                Toast.makeText(getApplicationContext(), "Error loading page", Toast.LENGTH_SHORT).show();
            }
        });

        webApp.loadUrl("https://comp-fyp.onrender.com/rfid_bookshelf.html");
    }
}