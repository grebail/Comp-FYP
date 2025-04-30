package com.example.libraryapp;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
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

import java.io.IOException;
import java.util.List;

public class MyLibraryActivity extends AppCompatActivity {

    WebView webApp;
    private static final String LOGIN_URL = "https://comp-fyp.onrender.com/login.html?from=app";

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            EdgeToEdge.enable(this);
            setContentView(R.layout.activity_mylibrary);
            ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
                Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
                v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
                return insets;
            });

            // Check if launched via deep link
            Intent intent = getIntent();
            if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
                Uri uri = intent.getData();
                if (uri != null && "myapp".equals(uri.getScheme()) && "main".equals(uri.getHost())) {
                    // Extract userid and token
                    String userid = uri.getQueryParameter("userid");
                    String token = uri.getQueryParameter("token");

                    // Save credentials
                    SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
                    prefs.edit().putString("userid", userid).putString("token", token).apply();

                    // Close the activity or proceed to main app screen
                    finish();
                    return;
                }
            }

            // Launch external browser for login if not already logged in
            SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
            if (!prefs.contains("userid") || !prefs.contains("token")) {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(LOGIN_URL));
                browserIntent.setPackage("com.android.chrome");
                startActivity(browserIntent);
                // Do not finish() here to allow deep link return
            } else {
                loadURL();
            }
        }

        private void loadURL() {
            // Start the shared AssetServer
            ServerManager.startServer(this);
            if (!ServerManager.isServerRunning()) {
                Toast.makeText(this, "Failed to start server", Toast.LENGTH_SHORT).show();
            }

            webApp = findViewById(R.id.webApp);
            WebSettings settings = webApp.getSettings();
            settings.setJavaScriptEnabled(true);
            settings.setCacheMode(WebSettings.LOAD_DEFAULT);
            webApp.clearCache(true);
            settings.setDomStorageEnabled(true);
            settings.setLoadWithOverviewMode(true);
            settings.setUseWideViewPort(true);

            webApp.setWebViewClient(new WebViewClient() {
                @Override
                public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                    String url = request.getUrl().toString();
                    if (url.startsWith("myapp://")) {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                        startActivity(intent);
                        finish(); // Close this activity
                        return true;
                    }
                    return super.shouldOverrideUrlLoading(view, request);
                }
            });

            webApp.loadUrl(LOGIN_URL);
        }

    private void handleDeepLink(Intent intent) {
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri uri = intent.getData();
            if (uri != null && "myapp".equals(uri.getScheme()) && "main".equals(uri.getHost())) {
                String userid = uri.getQueryParameter("userid");
                String token = uri.getQueryParameter("token");

                // Save credentials
                SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
                prefs.edit().putString("userid", userid).putString("token", token).apply();

                // Redirect to MainActivity
                Intent mainIntent = new Intent(this, MainActivity.class);
                mainIntent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(mainIntent);

            }
        }
    }
}