package util;

public class KeyManager {
	// 실제 운영 환경에서는 환경 변수나 Vault 등에서 가져와야 함
    private static final String SECRET_KEY = "finance-top-secret-key";

    public static String getSecretKey() {
        return SECRET_KEY;
    }
}
