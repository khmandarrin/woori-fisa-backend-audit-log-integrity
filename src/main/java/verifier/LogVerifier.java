package verifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import util.DefaultLogFormatter;
import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

/**
 * 감사 로그(audit.log) 변조/삭제/삽입/순서변경 검증기
 *
 * 검증 포인트:
 *  1) previousHash 체인이 직전 currentHash와 연결되는지 (삭제/삽입/순서 변경 탐지)
 *  2) currentHash == HMAC(message + previousHash, secretKey) 인지 (내용 수정 탐지)
 */
public class LogVerifier {

    private static final String GENESIS_PREV_HASH = "INIT_SEED_0000";
    private final LogFormatter formatter;

    // 기본 생성자
    public LogVerifier() {
        this(new DefaultLogFormatter());
    }

    // 커스텀 포맷터 주입 생성자
    public LogVerifier(LogFormatter formatter) {
        this.formatter = formatter;
    }

    public VerifyResult verify(Path auditLogPath) throws IOException {
        if (auditLogPath == null) {
            return VerifyResult.fail(0, "auditLogPath가 null 입니다.");
        }
        if (!Files.exists(auditLogPath)) {
            return VerifyResult.fail(0, "파일이 존재하지 않습니다: " + auditLogPath);
        }

        final String secretKey = KeyManager.getSecretKey();

        int lineNo = 0;
        int verified = 0;

        String expectedPrevHash = GENESIS_PREV_HASH;

        try (BufferedReader br = Files.newBufferedReader(auditLogPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;

                if (line.trim().isEmpty()) continue;

                try {
                    // 1. 포맷터를 이용해 라인 파싱
                    String[] parts = formatter.parse(line);
                    
                    // 2. 핵심 데이터 추출 (인터페이스에 정의된 메서드 활용)
                    String message = formatter.extractMessage(parts);
                    String currentHash = formatter.extractCurrentHash(parts);
                    String previousHash = formatter.extractPrevHash(parts);
                    

                    // 4. previousHash 체인 검증
                    if (!previousHash.equals(expectedPrevHash)) {
                        return VerifyResult.tampered(lineNo, "체인 끊김(삭제/삽입 의심)", expectedPrevHash, previousHash, line);
                    }

                    // 5. HMAC 무결성 검증 (내용 변조 확인)
                    String calculatedHash = HmacHasher.generateHmac(message + previousHash, secretKey);
                    if (!currentHash.equals(calculatedHash)) {
                        return VerifyResult.tampered(lineNo, "데이터 변조 탐지", calculatedHash, currentHash, line);
                    }

                    expectedPrevHash = currentHash;
                    verified++;

                } catch (Exception e) {
                    return VerifyResult.fail(lineNo, "검증 중 예외 발생: " + e.getMessage() + " / line=" + line);
                }
            }
        }

        return VerifyResult.ok(verified);
    }

    public static class VerifyResult {
        public final boolean valid;
        public final int verifiedLines;

        public final Integer tamperedLine; // null이면 정상
        public final String reason;
        public final String expected;
        public final String actual;
        public final String rawLine;

        private VerifyResult(
            boolean valid,
            int verifiedLines,
            Integer tamperedLine,
            String reason,
            String expected,
            String actual,
            String rawLine
        ) {
            this.valid = valid;
            this.verifiedLines = verifiedLines;
            this.tamperedLine = tamperedLine;
            this.reason = reason;
            this.expected = expected;
            this.actual = actual;
            this.rawLine = rawLine;
        }

        public static VerifyResult ok(int verifiedLines) {
            return new VerifyResult(true, verifiedLines, null, null, null, null, null);
        }

        public static VerifyResult fail(int lineNo, String reason) {
            return new VerifyResult(false, Math.max(0, lineNo - 1), lineNo, reason, null, null, null);
        }

        public static VerifyResult tampered(int lineNo, String reason, String expected, String actual, String rawLine) {
            return new VerifyResult(false, lineNo - 1, lineNo, reason, expected, actual, rawLine);
        }

        @Override
        public String toString() {
            if (valid) return "OK (verifiedLines=" + verifiedLines + ")";
            return "FAIL (verifiedLines=" + verifiedLines +
                   ", line=" + tamperedLine +
                   ", reason=" + reason +
                   (expected != null ? ", expected=" + expected : "") +
                   (actual != null ? ", actual=" + actual : "") +
                   (rawLine != null ? ", raw=" + rawLine : "") +
                   ")";
        }
    }
}
