package com.example.libraryapp;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
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

public class EventBookingActivity extends AppCompatActivity {
    private WebView webApp;
    private static final String LOGIN_URL = "https://comp-fyp.onrender.com/login.html?from=app";
    private static final String EVENT_BOOKING_BASE_URL = "https://comp-fyp.onrender.com/event_booking.html";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_event_booking); // Assuming this layout exists
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        loadEventBooking();
    }

    private void loadEventBooking() {
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
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                Toast.makeText(EventBookingActivity.this, "Error loading page: " + error.getDescription(), Toast.LENGTH_SHORT).show();
            }
        });

        SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
        String userid = prefs.getString("userid", null);
        String token = prefs.getString("token", null);

        if (userid != null && token != null) {
            String eventBookingUrl = EVENT_BOOKING_BASE_URL + "?userid=" + userid + "&token=" + token;
            webApp.loadUrl(eventBookingUrl);
        } else {
            handleMissingCredentials();
        }
    }

    private void handleMissingCredentials() {
        Toast.makeText(this, "Login required to access event booking", Toast.LENGTH_LONG).show();
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(LOGIN_URL));
        intent.setPackage("com.android.chrome");
        startActivity(intent);
        finish();
    }
}
