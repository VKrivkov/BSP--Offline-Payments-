package com.example.biometric

import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Button
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.example.biometric.ui.theme.BiometricTheme
import java.util.concurrent.Executor

class MainActivity : AppCompatActivity() {
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    CenteredContent(::handleButtonClick)
                }
            }
        }
        Log.d("MainActivity", "onCreate: Starting application setup")
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = createBiometricPrompt()
        promptInfo = createPromptInfo()
    }

    private fun createBiometricPrompt(): BiometricPrompt {
        val callback = object : BiometricPrompt.AuthenticationCallback() {

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e("BiometricPrompt", "onAuthenticationError: $errorCode, $errString")
                super.onAuthenticationError(errorCode, errString)
                // Handle error.
            }
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                Log.e("BiometricPrompt", "onAuthenticationError: Success")
                super.onAuthenticationSucceeded(result)
                // Handle success.
            }

            override fun onAuthenticationFailed() {
                Log.e("BiometricPrompt", "onAuthenticationError: FATAL ERROR")
                super.onAuthenticationFailed()
                // Handle failure.
            }
        }

        return BiometricPrompt(this, executor, callback)
    }

    private fun createPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric login for my app")
            .setSubtitle("Log in using your biometric credential")
            .setNegativeButtonText("Cancel") // Set a negative button text
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()
    }

    // Call this function when the button is clicked
    private fun handleButtonClick(){
        biometricPrompt.authenticate(promptInfo)
    }
}



@Composable
fun CenteredContent(onButtonClick: () -> Unit) {
    var inputText by remember { mutableStateOf(TextFieldValue("")) }
    var outputText by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        BasicTextField(
            value = inputText,
            onValueChange = { inputText = it },
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, Color.Gray)
                .padding(16.dp),
            decorationBox = { innerTextField ->
                if (inputText.text.isEmpty()) {
                    Text("Enter some text", color = Color.Gray)
                }
                innerTextField()
            }
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = {
                onButtonClick()
                outputText = "Output: ${inputText.text}"
            }
        ) {
            Text("Submit")
        }
        Spacer(modifier = Modifier.height(16.dp))
        if (outputText.isNotEmpty()) {
            Text(
                text = outputText,
                modifier = Modifier.border(1.dp, Color.Gray).padding(16.dp)
            )
        }
    }
}




@Preview(showBackground = true)
@Composable
fun CenteredContentPreview() {
    BiometricTheme {
        // Pass a dummy lambda function that does nothing on button click
        CenteredContent(onButtonClick = {})
    }
}
