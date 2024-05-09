package com.example.biometric

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.example.biometric.ui.theme.BiometricTheme
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executor


class MainActivity : AppCompatActivity() {
    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private var isAuthenticationInProgress by mutableStateOf(true) // Flag to track if authentication is in progress
    private var currentAuthContext = AuthContext.APP_LAUNCH
    private var initinputText by mutableStateOf("")
    private var initoutputText by mutableStateOf("")
    private var publicKey: PublicKey? = null


    enum class AuthContext {
        APP_LAUNCH,
        SIGN_DATA
    }


    @RequiresApi(Build.VERSION_CODES.S)
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
                    }
                }
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

            @RequiresApi(Build.VERSION_CODES.S)
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d("BiometricPrompt", "Authentication succeeded")
                when (currentAuthContext) {
                    AuthContext.APP_LAUNCH -> handleAppLaunch()
                    AuthContext.SIGN_DATA -> {
                            try {
                                val signature = result.cryptoObject?.signature
                                if (signature != null && currentAuthContext == AuthContext.SIGN_DATA) {
                                    signature.update(initinputText.toByteArray())
                                    val signedData = signature.sign()
                                    initoutputText =
                                        "Signed Output: ${bytesToHex(signedData)}; Public Key: $publicKey"
                                    updateUI(initoutputText)
                                } else {
                                    initoutputText =
                                        "Crypto object is not available or context is incorrect."
                                    updateUI(initoutputText)
                                }
                            } catch (e: Exception) {
                                Log.e("MainActivity", "Signing error: ${e.localizedMessage}")
                                initoutputText = "Signing error: ${e.localizedMessage}"
                                updateUI(initoutputText)

                        }
                    }
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

    @RequiresApi(Build.VERSION_CODES.S)
    private fun handleAppLaunch(){
        setContent {
            BiometricTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AuthenticationScreen(
                        "",
                        "",
                        ::handleButtonClick,
                        ::isKeyPairInsideSecurityHardware,
                        ::updateSharedInputText
                    )
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
    @RequiresApi(Build.VERSION_CODES.S)
    private fun handleButtonClick() {
        generateKeyPair()
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val privateKey = keyStore.getKey("biometricKeyAliasRSA", null) as? PrivateKey
            val signature = Signature.getInstance("SHA256WithRSA")
            signature.initSign(privateKey)
            val cryptoObject = BiometricPrompt.CryptoObject(signature)
            currentAuthContext = AuthContext.SIGN_DATA
            biometricPrompt.authenticate(
                promptInfo,
                cryptoObject
            )  // Pass the CryptoObject here
        } catch (e: Exception) {
            Log.e("MainActivity", "Error setting up signature: ${e.localizedMessage}")
        }
    }


    @RequiresApi(Build.VERSION_CODES.S)
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
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                "biometricKeyAliasRSA",
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests (KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setAttestationChallenge("attestation_challenge_RSA".toByteArray())
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1) //Set of padding schemes with which the key can be used when signing/verifying
                .setIsStrongBoxBacked(true)
                .build()
            keyPairGenerator.initialize(parameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()
            publicKey = keyPair.public
            Log.d("MainActivity", "Key pair generated successfully")
        } catch (e: java.lang.Exception) {
            Log.e("MainActivity", "Key pair generation failed", e)
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




    @RequiresApi(Build.VERSION_CODES.S)
    private fun isKeyPairInsideSecurityHardware()  {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve the private key; this is the correct approach as KeyInfo only works with private keys
            val privateKey = keyStore.getKey("biometricKeyAliasRSA", null) as? PrivateKey
                ?: throw Exception("No private key found under the given alias.")

            val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            val secLevel = keyInfo.securityLevel

            Log.d("SecurityLevel", "Is key inside secure hardware: $secLevel")


            val certificateChain: Array<Certificate> = keyStore.getCertificateChain("biometricKeyAliasRSA") as? Array<Certificate>
                ?: throw Exception("Certificate chain not found for alias.")
            // Serialize certificates to PEM format for logging or transmission
            val certificates = certificateChain.joinToString(separator = "\n") { cert ->
                val encoded = Base64.getEncoder().encodeToString(cert.encoded)
                "-----BEGIN CERTIFICATE-----\n" + encoded.chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----"
            }

            Log.d("CertificateChain", "Certificate chain: ${certificateChain.size} |||||||||| ${certificates}")
            sendCertificate(certificates);

        } catch (e: Exception) {
            Log.e("CertificateRetrieval", "Error retrieving certificate chain", e)
        }
    }


    private fun sendCertificate(Certificates: String) {
        val client = OkHttpClient()

        val json = JSONObject()
        try {
            json.put("CertificateChain", Certificates)
        } catch (e: JSONException) {
            e.printStackTrace()
        }

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val body = json.toString().toRequestBody(mediaType)

        val request = Request.Builder()
            .url("http://54.93.52.63:3456/submit-certificate")
            .post(body)
            .build()

        Thread {
            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) throw IOException("Unexpected code $response")

                    val responseBody = response.body?.string() ?: "No response"
                    // Run on the UI thread to show Toast
                    runOnUiThread {
                        Toast.makeText(this@MainActivity, responseBody, Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                // Run on the UI thread to show Toast
                runOnUiThread {
                    Toast.makeText(this@MainActivity, "Error sending certificate: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()

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
    isKeyPairInsideSecurityHardware:() -> Unit,
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
                modifier = Modifier
                    .border(1.dp, Color.Gray)
                    .padding(16.dp)
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


