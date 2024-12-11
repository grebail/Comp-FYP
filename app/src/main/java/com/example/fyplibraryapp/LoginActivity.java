package com.example.fyplibraryapp;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

public class LoginActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        Button loginButton = findViewById(R.id.loginButton);
        loginButton.setOnClickListener(v -> login());
    }

    private void login() {
        EditText emailEditText = findViewById(R.id.userEditText);
        EditText passwordEditText = findViewById(R.id.passwordEditText);
        String email = emailEditText.getText().toString();
        String password = passwordEditText.getText().toString();

        // Here you would normally validate the credentials
        // For example, using Firebase Authentication or your own backend

        // If login is successful
        Intent intent = new Intent(LoginActivity.this, MainActivity.class);
        intent.putExtra("USERNAME", email); // Pass the email to MainActivity
        startActivity(intent);
        finish(); // Finish login activity
    }

    public void onRegisterClick(View view) {
        Intent intent = new Intent(this, RegisterActivity.class);
        startActivity(intent);
    }
}
