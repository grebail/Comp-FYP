package com.example.libraryapp;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.GridLayout;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        handleDeepLink(getIntent());

        Intent intent = getIntent();
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri uri = intent.getData();
            if (uri != null && "myapp".equals(uri.getScheme()) && "main".equals(uri.getHost())) {
                // Deep link confirmed as myapp://main
                Toast.makeText(this, "Welcome, you can continue to use the app.", Toast.LENGTH_SHORT).show();
            }
        }

        Button userGuideButton = findViewById(R.id.userGuideButton);
        Button myLibraryButton = findViewById(R.id.myLibraryButton);
        Button scanBorrowButton = findViewById(R.id.scanBorrowButton);
        Button bookMapButton = findViewById(R.id.bookMapButton);
        Button roomBookButton = findViewById(R.id.roomBookButton);
        Button eventBookButton = findViewById(R.id.eventBookButton);

        myLibraryButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, MyLibraryActivity.class));
            }
        });

        scanBorrowButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, ScannerQRActivity.class));
            }
        });

        bookMapButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, BookLocationActivity.class));
            }
        });

        roomBookButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, RoomBookingActivity.class));
            }
        });

        eventBookButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, EventBookingActivity.class));
            }
        });

        userGuideButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showUserGuideDialog();
            }
        });
    }

    private void showUserGuideDialog() {
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(R.layout.user_guide)
                .create();
        dialog.show();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // Handle deep link if MainActivity is already open
        handleDeepLink(intent);
    }

    private void handleDeepLink(Intent intent) {
        if (intent != null && Intent.ACTION_VIEW.equals(intent.getAction())) {
            Uri uri = intent.getData();
            if (uri != null && "myapp".equals(uri.getScheme()) && "main".equals(uri.getHost())) {
                String userid = uri.getQueryParameter("userid");
                String token = uri.getQueryParameter("token");
                String from = uri.getQueryParameter("from");

                SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString("userid", userid);
                editor.putString("token", token);
                editor.apply();

                if ("MyLibrary".equals(from)) {
                    startActivity(new Intent(this,MyLibraryActivity.class));
                } else if ("RoomBooking".equals(from)) {
                    startActivity(new Intent(this, RoomBookingActivity.class));
                } else if ("EventBooking".equals(from)) {
                    startActivity(new Intent(this, EventBookingActivity.class));
                } else {
                    Toast.makeText(this, "Welcome back, " + userid + "!", Toast.LENGTH_SHORT).show();
                }
            }
        }
    }
}