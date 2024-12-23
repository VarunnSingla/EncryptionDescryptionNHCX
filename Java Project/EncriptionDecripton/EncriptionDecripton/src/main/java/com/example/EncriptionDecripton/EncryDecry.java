package com.example.EncriptionDecripton;

/*import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openssl.PEMParser;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
*/

import java.io.FileReader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openssl.PEMParser;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

public class EncryDecry {


    public static final String KEY_MANAGEMENT_ALGORITHM = KeyManagementAlgorithmIdentifiers.RSA_OAEP_256;
    public static final String CONTENT_ENCRYPTION_ALGORITHM = ContentEncryptionAlgorithmIdentifiers.AES_256_GCM;
    private Map<String, Object> headers;
    private String payload;

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public String getPayload() {
        return payload;
    }

    public String encryptRequest(PublicKey rsaPublicKey, String payload, Map<String, Object> header) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(payload);
        jwe.setAlgorithmHeaderValue(KEY_MANAGEMENT_ALGORITHM);
        jwe.setEncryptionMethodHeaderParameter(CONTENT_ENCRYPTION_ALGORITHM);

        // Set individual headers
        for (Map.Entry<String, Object> entry : header.entrySet()) {
            jwe.setHeader(entry.getKey(), entry.getValue().toString());
        }

        jwe.setKey(rsaPublicKey);
        return jwe.getCompactSerialization();
    }

    public void decryptRequest(PrivateKey rsaPrivateKey, String encryptedObject) throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(encryptedObject);
        jwe.setKey(rsaPrivateKey);
        payload = jwe.getPlaintextString();

        // Retrieve headers
		/*
		 * headers = new HashMap<>(); for (String headerName :
		 * jwe.getHeaders().getHeaderNames()) { headers.put(headerName,
		 * jwe.getHeaders().getStringHeaderValue(headerName)); }
		 */
        
        headers = new HashMap<>();
        
        headers.put("alg",jwe.getHeaders().getStringHeaderValue("alg"));
        headers.put("enc",jwe.getHeaders().getStringHeaderValue("enc"));
        headers.put("x-hcx-api_call_id",jwe.getHeaders().getStringHeaderValue("x-hcx-api_call_id"));
        headers.put("x-hcx-workflow_id",jwe.getHeaders().getStringHeaderValue("x-hcx-workflow_id"));
        
        headers.put("x-hcx-request_id",jwe.getHeaders().getStringHeaderValue("x-hcx-request_id"));
        headers.put("x-hcx-status",jwe.getHeaders().getStringHeaderValue("x-hcx-status"));
        headers.put("x-hcx-timestamp",jwe.getHeaders().getStringHeaderValue("x-hcx-timestamp"));
        headers.put("x-hcx-sender_code",jwe.getHeaders().getStringHeaderValue("x-hcx-sender_code"));
        
        headers.put("x-hcx-recipient_code",jwe.getHeaders().getStringHeaderValue("x-hcx-recipient_code"));
        headers.put("x-hcx-correlation_id",jwe.getHeaders().getStringHeaderValue("x-hcx-correlation_id"));

        
    }


    public PrivateKey getRSAPrivateKeyFromPem(String pemPath) throws Exception {
        try {
            String key = new String(Files.readAllBytes(Paths.get(pemPath)));
            String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception ex) {
            throw new Exception("[PrivateKey reading error] " + ex);
        }
    }
    

    public PublicKey getRSAPublicKeyFromPem(String pemPath) throws Exception {
        try (FileReader reader = new FileReader(pemPath);
             PEMParser pemParser = new PEMParser(reader)) {
        			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(Files.newInputStream(Paths.get(pemPath)));
            return certificate.getPublicKey();
        } catch (Exception ex) {
            throw new Exception("[PublicKey reading error] " + ex.getMessage());
        }
    }
}