package com.example.biometric

import android.os.Build
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
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import kotlin.reflect.KFunction0
import kotlin.reflect.KFunction1



class MainActivity : AppCompatActivity() {
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private var isAuthenticationInProgress by mutableStateOf(true) // Flag to track if authentication is in progress
    private var currentAuthContext = AuthContext.APP_LAUNCH
    private var initinputText by mutableStateOf("")
    private var initoutputText by mutableStateOf("")



    enum class AuthContext {
        APP_LAUNCH,
        SIGN_DATA
    }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    if (isAuthenticationInProgress) {
                        // Show default placeholder screen while authentication is in progress
                        DefaultScreen()
                    } else {
                        // Show authentication screen if authentication is successful
                        AuthenticationScreen("", "", ::handleButtonClick, ::isKeyPairInsideSecurityHardware, ::updateSharedInputText)
                    }               }
            }
        }
        Log.d("MainActivity", "onCreate: Starting application setup")
        executor = ContextCompat.getMainExecutor(this)
        biometricPrompt = createBiometricPrompt()
        promptInfo = createPromptInfo()
        biometricPrompt.authenticate(promptInfo)
        triggerBiometricAuthentication(AuthContext.APP_LAUNCH)

    }

    private fun triggerBiometricAuthentication(context: AuthContext) {
        currentAuthContext = context
        biometricPrompt.authenticate(promptInfo)
    }

    private fun createBiometricPrompt(): BiometricPrompt {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e("BiometricPrompt", "onAuthenticationError: $errorCode, $errString")
                super.onAuthenticationError(errorCode, errString)
                showAuthenticationFailedScreen()
            }

            @RequiresApi(Build.VERSION_CODES.R)
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d("BiometricPrompt", "Authentication succeeded")
                when (currentAuthContext) {
                    AuthContext.APP_LAUNCH -> handleAppLaunch()
                    AuthContext.SIGN_DATA -> handleSigning()
                }
            }

            override fun onAuthenticationFailed() {
                Log.e("BiometricPrompt", "onAuthenticationError: FATAL ERROR")
                super.onAuthenticationFailed()
                showAuthenticationFailedScreen()
            }
        }

        return BiometricPrompt(this, executor, callback)
    }

    private fun handleAppLaunch(){
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AuthenticationScreen("", "", ::handleButtonClick, ::isKeyPairInsideSecurityHardware, ::updateSharedInputText)
                }
            }
        }
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
    private fun handleButtonClick() {
        currentAuthContext = AuthContext.SIGN_DATA
        biometricPrompt.authenticate(promptInfo)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun handleSigning(){
        generateKeyPair()
        val signedData = signData(initinputText)
        initoutputText = "Signed Output: ${signedData?.let { bytesToHex(it) }}"
        updateUI(initoutputText)

    }

    private fun updateUI(text: String) {
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AuthenticationScreen(initinputText, text, ::handleButtonClick, ::isKeyPairInsideSecurityHardware, ::updateSharedInputText)
                }
            }
        }
    }

    private fun updateSharedInputText(newText: String) {
        initinputText = newText
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun generateKeyPair() {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                "biometricKeyAlias",
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).apply {
                setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                setUserAuthenticationRequired(true)
                setUserAuthenticationParameters(3, KeyProperties.AUTH_BIOMETRIC_STRONG) // Adjust based on your requirement
            }.build()
            keyPairGenerator.initialize(parameterSpec)
            keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            Log.e("MainActivity", "Key pair generation failed", e)
        }
    }

    private fun signData(input: String): ByteArray? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val privateKey = keyStore.getKey("biometricKeyAlias", null) as? PrivateKey
        val signature = Signature.getInstance("SHA256withECDSA")

        return privateKey?.let {
            signature.initSign(it)
            signature.update(input.toByteArray())
            signature.sign()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val hexArray = "0123456789ABCDEF".toCharArray()
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    private fun showAuthenticationFailedScreen() {
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AuthenticationFailedScreen(::retryBiometricAuthentication)
                }
            }
        }
    }

    private fun retryBiometricAuthentication() {
        biometricPrompt.authenticate(promptInfo)
    }




    private fun isKeyPairInsideSecurityHardware(): Boolean {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve the KeyGenParameterSpec from the KeyPairGenerator
            val keyGenParameterSpec = keyStore.getKey("biometricKeyAlias", null)?.let { entry ->
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                )
                keyPairGenerator.initialize(null, null)
                keyPairGenerator.javaClass.getDeclaredMethod("getKeyGenParameterSpec", entry.javaClass).invoke(keyPairGenerator, entry) as KeyGenParameterSpec
            }

            if (keyGenParameterSpec != null) {
                return keyGenParameterSpec.isStrongBoxBacked
            }


        } catch (e: Exception) {
            Log.e("MainActivity", "Error checking if key pair is inside secure hardware", e)
        }
        return false
    }



}


@Composable
fun DefaultScreen() {
    // Placeholder screen while authentication is in progress
    Text("Loading...")
}


@Composable
fun AuthenticationScreen(
    initInputText: String,
    outputText: String, // Now passed directly and used as read-only
    onButtonClick: () -> Unit,
    isKeyPairInsideSecurityHardware: () -> Boolean,
    updateInputText: (String) -> Unit // Function to update text

) {
    var inputText by remember { mutableStateOf(initInputText) }


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
                if (inputText.isEmpty()) {
                    Text("Enter some text", color = Color.Gray)
                }
                innerTextField()
            }
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick ={
            onButtonClick()
            updateInputText(inputText)
        }) {
            Text("Submit")
        }
        Spacer(modifier = Modifier.height(16.dp))
        if (outputText.isNotEmpty()) {
            Text(
                text = outputText,
                modifier = Modifier.border(1.dp, Color.Gray).padding(16.dp)
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = {
            val info = isKeyPairInsideSecurityHardware()
            Log.e("ORIGIN VERIFICATION", info.toString())
        }) {
            Text("Verify")
        }
    }
}



@Composable
fun AuthenticationFailedScreen(onRetryClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Authentication failed, please try again")
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onRetryClick) {
            Text("Retry Authentication")
        }
    }
}


