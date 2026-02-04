package util;

import java.io.InputStream;
import java.util.Properties;

public class KeyManager {
	// static final로 선언하여 런타임 중 변경 불가능하게 설정
    private static final String SECRET_KEY;
    private static final String CONFIG_FILE = "audit.properties";

    static {
        try {
            SECRET_KEY = loadKey();
        } catch (Exception e) {
            // static 블록에서 예외가 발생하면 클래스 로딩이 실패하며 시스템이 멈춤
            throw new ExceptionInInitializerError(" [Critical] 감사 로그용 보안 키를 로드할 수 없습니다. 시스템을 종료합니다. : " + e.getMessage());
        }
    }

    private static String loadKey() throws Exception {
        Properties prop = new Properties();
        
        try (InputStream input = KeyManager.class.getClassLoader().getResourceAsStream(CONFIG_FILE)) {
            if (input == null) {
                throw new RuntimeException(CONFIG_FILE + " 파일을 찾을 수 없습니다.");
            }

            prop.load(input);
            String key = prop.getProperty("audit.secret.key");

            // 키가 비어있거나 null인 경우 예외 발생 (가장 중요한 체크)
            if (key == null || key.trim().isEmpty()) {
                throw new RuntimeException("audit.secret.key 값이 설정되어 있지 않습니다.");
            }

            return key;
        }
    }

    public static String getSecretKey() {
        return SECRET_KEY;
    }
}
