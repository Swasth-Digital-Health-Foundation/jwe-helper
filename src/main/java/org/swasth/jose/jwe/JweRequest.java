package org.swasth.jose.jwe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.util.Base64URL;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

public class JweRequest implements JweRequestInterface {

    public static final JWEAlgorithm KEY_MANAGEMENT_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;
    public static final EncryptionMethod CONTENT_ENCRYPTION_ALGORITHM = EncryptionMethod.A256GCM;

    private Map<String, Object> headers;
    private Map<String, Object> payload;

    private Map<String, String> encryptedObject;

    private Map<String, String> deserializedObject;

    public JweRequest(Map<String, Object> headers, Map<String, Object> payload) {
        this.headers = headers;
        this.payload = payload;
    }

    public JweRequest(Map<String, String> encryptedObject) {
        this.encryptedObject = encryptedObject;
    }

    public Map<String, String> getEncryptedObject() {
        return encryptedObject;
    }

    public Map<String, Object> getHeaders() {
        return headers;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void encryptRequest(RSAPublicKey rsaPublicKey) throws JOSEException {
        JWEHeader jweHeader = new JWEHeader.Builder(KEY_MANAGEMENT_ALGORITHM, CONTENT_ENCRYPTION_ALGORITHM)
                .customParams(headers).build();
        Payload jwePayload = new Payload(this.payload);
        JWEObject jweObject = new JWEObject(jweHeader, jwePayload);
        RSAEncrypter rsaEncrypter = new RSAEncrypter(rsaPublicKey);
        jweObject.encrypt(rsaEncrypter);
        String serializedString = jweObject.serialize();
        encryptedObject = new HashMap<>();
        encryptedObject.put("payload", serializedString);
    }

    private void buildEncryptedObjectFromString(String serializedString) {
        String[] jweParts = serializedString.split("\\.");
        this.deserializedObject = new HashMap<>();
        this.deserializedObject.put("protected", jweParts[0]);
        this.deserializedObject.put("encrypted_key", jweParts[1]);
        this.deserializedObject.put("iv", jweParts[2]);
        this.deserializedObject.put("ciphertext", jweParts[3]);
        this.deserializedObject.put("tag", jweParts[4]);
    }

    public void decryptRequest(RSAPrivateKey rsaPrivateKey) throws ParseException, JOSEException {
        buildEncryptedObjectFromString(encryptedObject.get("payload"));
        JWEObject jweObject = new JWEObject(new Base64URL(this.deserializedObject.get("protected")),
                new Base64URL(this.deserializedObject.get("encrypted_key")),
                new Base64URL(this.deserializedObject.get("iv")),
                new Base64URL(this.deserializedObject.get("ciphertext")),
                new Base64URL(this.deserializedObject.get("tag")));
        JWEDecrypter jweDecrypter = new RSADecrypter(rsaPrivateKey);
        jweObject.decrypt(jweDecrypter);
        this.headers = jweObject.getHeader().toJSONObject();
        this.payload = new HashMap<>(jweObject.getPayload().toJSONObject());
    }

}
