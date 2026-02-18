package com.mega.provider

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LoginActivity : AppCompatActivity() {

    private lateinit var emailInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var loginButton: Button
    private lateinit var logoutButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var statusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        emailInput = findViewById(R.id.email_input)
        passwordInput = findViewById(R.id.password_input)
        loginButton = findViewById(R.id.login_button)
        logoutButton = findViewById(R.id.logout_button)
        progressBar = findViewById(R.id.progress_bar)
        statusText = findViewById(R.id.status_text)

        // If already logged in, show status
        if (MegaSessionManager.hasSession(this)) {
            showLoggedInState()
            // Try to resume session in background
            resumeSession()
        }

        loginButton.setOnClickListener { performLogin() }
        logoutButton.setOnClickListener { performLogout() }
    }

    private fun showLoggedInState() {
        emailInput.visibility = View.GONE
        passwordInput.visibility = View.GONE
        loginButton.visibility = View.GONE
        logoutButton.visibility = View.VISIBLE
        statusText.visibility = View.VISIBLE
        statusText.text = getString(R.string.logged_in_message)
    }

    private fun showLoggedOutState() {
        emailInput.visibility = View.VISIBLE
        passwordInput.visibility = View.VISIBLE
        loginButton.visibility = View.VISIBLE
        logoutButton.visibility = View.GONE
        statusText.visibility = View.GONE
        emailInput.text.clear()
        passwordInput.text.clear()
    }

    private fun performLogin() {
        val email = emailInput.text.toString().trim()
        val password = passwordInput.text.toString()

        if (email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, R.string.fill_fields, Toast.LENGTH_SHORT).show()
            return
        }

        setLoading(true)

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val session = MegaClientHolder.login(email, password)
                MegaSessionManager.saveSession(this@LoginActivity, session)

                withContext(Dispatchers.Main) {
                    setLoading(false)
                    Toast.makeText(
                        this@LoginActivity,
                        R.string.login_success,
                        Toast.LENGTH_SHORT
                    ).show()
                    showLoggedInState()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    Toast.makeText(
                        this@LoginActivity,
                        getString(R.string.login_failed, e.message),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun resumeSession() {
        val session = MegaSessionManager.getSession(this) ?: return

        CoroutineScope(Dispatchers.IO).launch {
            val ok = MegaClientHolder.fastLogin(session)
            if (!ok) {
                // Session expired — clear and show login
                MegaSessionManager.clearSession(this@LoginActivity)
                withContext(Dispatchers.Main) {
                    showLoggedOutState()
                    Toast.makeText(
                        this@LoginActivity,
                        R.string.session_expired,
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun performLogout() {
        MegaClientHolder.logout()
        MegaSessionManager.clearSession(this)
        showLoggedOutState()
        Toast.makeText(this, R.string.logged_out, Toast.LENGTH_SHORT).show()
    }

    private fun setLoading(loading: Boolean) {
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        loginButton.isEnabled = !loading
        emailInput.isEnabled = !loading
        passwordInput.isEnabled = !loading
    }
}
