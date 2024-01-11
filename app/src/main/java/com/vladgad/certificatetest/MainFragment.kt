package com.vladgad.certificatetest

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.vladgad.certificatetest.databinding.FragmentMainBinding
import java.io.File
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.CertificateFactory


class MainFragment : Fragment() {
    private var _binding: FragmentMainBinding? = null
    protected val binding get() = _binding!!
    private val ALIAS = "CRT_ALIAS"
    private val mTag = "MainFragment"
    private lateinit var cryptography: Cryptography
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentMainBinding.inflate(inflater, container, false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!Environment.isExternalStorageManager()) {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                val uri: Uri = Uri.fromParts("package", activity?.packageName, null)
                intent.data = uri
                startActivity(intent)
            }
        }


        cryptography = Cryptography(requireContext())

        binding.generateCert.setOnClickListener {
            cryptography.generateKeys(ALIAS)
            generatePairKeys()
        }
        binding.saveCert.setOnClickListener {
            val cert = cryptography.geCertificate(ALIAS)
            val file = File(Environment.getExternalStorageDirectory().toString() + "/cert.crt")
            file.outputStream().write(cert.encoded)
            val x = 1
        }
        binding.saveCertLib.setOnClickListener {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            val keyPair = keyPairGenerator.generateKeyPair()
            val cert =  Cryptography.generateV3Certificate(keyPair,ALIAS)
            /*val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(1024, SecureRandom())
            val keyPair = keyPairGenerator.generateKeyPair()

            val notBefore = ZonedDateTime.now()
            val notAfter = notBefore.plusYears(10)

            val cert = X509Generator(X509Generator.Algorithm.RSA_SHA256)
                .generate(
                    subject = mapOf(
                        "CN" to "Certificate Example",
                        "O" to "IT",
                        "SubjectAlternativeName" to "10.10.10.11"
                    ),
                    issuer = mapOf("CN" to "Certificate Issuer"),
                    notBefore = notBefore,
                    notAfter = notAfter,
                    serialNumber = 1337,
                    keyPair = keyPair
                )*/
              val file = File(Environment.getExternalStorageDirectory().toString()+"/certLibB.crt")
              file.outputStream().write(cert.encoded)
        }
        return binding.root
    }


    private fun generatePairKeys() {
        /*val spec = KeyGenParameterSpec.Builder(context!!)
            .setAlias(alias)
            .setSubject(X500Principal("CN=$alias"))
            .setSerialNumber(BigInteger.valueOf(Math.abs(alias.hashCode()).toLong()))
            .setStartDate(start.getTime()).setEndDate(end.getTime())
            .build()*/
        val kpGenerator = KeyPairGenerator.getInstance(
            "RSA"
            /*,
            "AndroidKeyStore"*/
        )
        kpGenerator.initialize(2048, SecureRandom())

        val keyPair = kpGenerator.generateKeyPair()
        val certificateBuild = CertificateFactory.getInstance("X.509")


        Log.d(mTag, "Public Key is " + keyPair.public.toString().toByteArray())
    }
}