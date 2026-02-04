package verifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import util.HmacHasher;
import util.KeyManager;

/**
 * 감사 로그(audit.log) 변조/삭제/삽입/순서변경 검증기
 *
 * 로그 포맷 (IntegrityAuditAppender):
 *  timestamp | message | currentHash | previousHash
 *
 * 검증 포인트:
 *  1) previousHash 체인이 직전 currentHash와 연결되는지 (삭제/삽입/순서 변경 탐지)
 *  2) currentHash == HMAC(message + previousHash, secretKey) 인지 (내용 수정 탐지)
 *  3) (옵션) timestamp가 단조 증가인지 (시간 순서 뒤바뀜 탐지)
 */
public class LogVerifier {

    private static final String GENESIS_PREV_HASH = "INIT_SEED_0000";

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
        long lastTimestamp = Long.MIN_VALUE;

        try (BufferedReader br = Files.newBufferedReader(auditLogPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;

                if (line.trim().isEmpty()) continue;

                ParsedLog pl;
                try {
                    pl = parse(line);
                } catch (IllegalArgumentException e) {
                    return VerifyResult.fail(lineNo, "로그 파싱 실패: " + e.getMessage() + " / raw=" + line);
                }

                // (옵션) timestamp 순서 검증: 시간 역행 감지
                if (pl.timestamp < lastTimestamp) {
                    return VerifyResult.tampered(
                        lineNo,
                        "타임스탬프 순서가 역행했습니다(시간 순서 뒤바뀜)",
                        "previousTimestamp=" + lastTimestamp,
                        "currentTimestamp=" + pl.timestamp,
                        line
                    );
                }
                lastTimestamp = pl.timestamp;

                // 1) previousHash 체인 검증
                if (!pl.previousHash.equals(expectedPrevHash)) {
                    return VerifyResult.tampered(
                        lineNo,
                        "previousHash 체인 불일치(삭제/삽입/순서 변경 의심)",
                        "expectedPrevHash=" + expectedPrevHash,
                        "actualPrevHash=" + pl.previousHash,
                        line
                    );
                }

                // 2) currentHash 무결성 검증
                final String expectedCurrentHash;
                try {
                    expectedCurrentHash = HmacHasher.generateHmac(pl.message + pl.previousHash, secretKey);
                } catch (Exception e) {
                    return VerifyResult.fail(lineNo, "HMAC 계산 실패: " + e.getMessage());
                }

                if (!pl.currentHash.equals(expectedCurrentHash)) {
                    return VerifyResult.tampered(
                        lineNo,
                        "currentHash 불일치(내용 수정/위조 의심)",
                        "expectedCurrentHash=" + expectedCurrentHash,
                        "actualCurrentHash=" + pl.currentHash,
                        line
                    );
                }

                // 다음 줄 기대 prevHash 업데이트
                expectedPrevHash = pl.currentHash;
                verified++;
            }
        }

        return VerifyResult.ok(verified);
    }

    /**
     * "timestamp | message | currentHash | previousHash" 파싱
     * - 구분자는 Appender의 String.format("%d | %s | %s | %s")와 동일하게 처리
     */
    private ParsedLog parse(String rawLine) {
        // " | " 기준으로 정확히 4개로 분리 (message 안에 " | "가 들어가면 깨질 수 있음)
        // → 현재 포맷에서는 message에 " | "를 넣지 않는다는 전제
        String[] parts = rawLine.split("\\s\\|\\s", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("필드 개수 불일치(4개 필요). parts=" + parts.length);
        }

        long ts;
        try {
            ts = Long.parseLong(parts[0].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("timestamp가 숫자가 아님: " + parts[0]);
        }

        String msg = parts[1].trim();
        String cur = parts[2].trim();
        String prev = parts[3].trim();

        if (msg.isEmpty()) throw new IllegalArgumentException("message가 비어있음");
        if (cur.isEmpty()) throw new IllegalArgumentException("currentHash가 비어있음");
        if (prev.isEmpty()) throw new IllegalArgumentException("previousHash가 비어있음");

        return new ParsedLog(ts, msg, cur, prev);
    }

    private static class ParsedLog {
        final long timestamp;
        final String message;
        final String currentHash;
        final String previousHash;

        ParsedLog(long timestamp, String message, String currentHash, String previousHash) {
            this.timestamp = timestamp;
            this.message = message;
            this.currentHash = currentHash;
            this.previousHash = previousHash;
        }
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
