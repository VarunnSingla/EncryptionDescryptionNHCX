package com.example.EncriptionDecripton;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jose4j.lang.JoseException;

public class PayloadMain {

	public static void main(String[] args) {

		// TODO Auto-generated method stub
		EncryDecry encryDecry = new EncryDecry();
        String encryptedObject = "";

        try {
            // Read payload from file
            String payload = new String(Files.readAllBytes(Paths.get("C:\\Users\\BK527HS\\OneDrive - EY\\Desktop\\Atul\\NHCX\\JWE\\InsurancePlan.txt")));

            // Create headers
            Map<String, Object> headers = new HashMap<>();

            headers.put("alg","RSA-OAEP-256");
            headers.put("enc","A256GCM");
            headers.put("x-hcx-api_call_id","bbea0ea1-2750-4ec8-8974-d3edc7030913");
            headers.put("x-hcx-workflow_id","1");
            
            headers.put("x-hcx-request_id","1113f541-6387-4c2a-ad3e-4bebc5a9fe36");
            headers.put("x-hcx-status","request.initiate");
            headers.put("x-hcx-timestamp","2023-08-02T14:57:40+0530");
            headers.put("x-hcx-sender_code","1000000046@sbx");
            
            headers.put("x-hcx-recipient_code","1000000109@sbx");
            headers.put("x-hcx-correlation_id","3a2ba13b-04f5-4943-9b50-a1334e55c90e");

            
         // Encryption Method Start
            PublicKey publicKey = encryDecry.getRSAPublicKeyFromPem("C:\\Users\\BK527HS\\OneDrive - EY\\Desktop\\Atul\\NHCX\\JWE\\SampleKey\\x509-self-signed-certificate.pem");
            encryptedObject = encryDecry.encryptRequest(publicKey, payload, headers);
            System.out.println("Encripted Payload: " + encryptedObject);
            // Encryption Method End

            // Decryption Method Start
            PrivateKey privateKey = encryDecry.getRSAPrivateKeyFromPem("C:\\Users\\BK527HS\\OneDrive - EY\\Desktop\\Atul\\NHCX\\JWE\\SampleKey\\x509-private-key.pem");
            encryDecry.decryptRequest(privateKey, encryptedObject);
            Map<String, Object> decryptedHeaders = encryDecry.getHeaders();
            String decryptedPayload = new ObjectMapper().writeValueAsString(encryDecry.getPayload());
            // Decryption Method End

            // Output the decrypted headers and payload
            System.out.println("Decrypted Headers: " + decryptedHeaders);
            System.out.println("Decrypted Payload: " + decryptedPayload);
            
            

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}