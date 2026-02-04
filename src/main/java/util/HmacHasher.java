package util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class HmacHasher {
    private static final String ALGORITHM = "HmacSHA256";

    /**
     * @param data 로깅할 메시지 + 이전 해시
     * @param key 보안 키 (환경변수 등에서 가져올 값)
     * @return Base64로 인코딩된 HMAC 해시값
     */
    public static String generateHmac(String data, String key) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(secretKeySpec);
        
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}