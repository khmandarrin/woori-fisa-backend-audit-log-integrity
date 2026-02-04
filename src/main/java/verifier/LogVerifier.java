package verifier;

import java.io.BufferedReader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

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

    public VerifyAllResult verifyAll(Path auditLogPath) throws IOException {
        if (auditLogPath == null) {
            return VerifyAllResult.fail("auditLogPath가 null 입니다.");
        }
        if (!Files.exists(auditLogPath)) {
            return VerifyAllResult.fail("파일이 존재하지 않습니다: " + auditLogPath);
        }

        final String secretKey = KeyManager.getSecretKey();

        int lineNo = 0;
        int verified = 0;

        String expectedPrevHash = GENESIS_PREV_HASH;
        long lastTimestamp = Long.MIN_VALUE;

        boolean chainBroken = false; // 한번 깨지면 이후 문제는 연쇄(cascade)로 표시
        List<Issue> issues = new ArrayList<>();

        try (BufferedReader br = Files.newBufferedReader(auditLogPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;

                if (line.trim().isEmpty()) continue;

                ParsedLog pl;
                try {
                    pl = parse(line);
                } catch (IllegalArgumentException e) {
                    issues.add(Issue.parseError(lineNo, e.getMessage(), line, chainBroken));
                    chainBroken = true;
                    continue;
                }

                // (옵션) timestamp 역행 체크
                if (pl.timestamp < lastTimestamp) {
                    issues.add(Issue.timestampRollback(lineNo, lastTimestamp, pl.timestamp, line, chainBroken));
                    chainBroken = true;
                }
                lastTimestamp = pl.timestamp;

                // 1) 체인 연결 체크: expectedPrevHash vs 로그 prev
                if (!pl.previousHash.equals(expectedPrevHash)) {
                    issues.add(Issue.prevHashMismatch(lineNo, expectedPrevHash, pl.previousHash, line, chainBroken));
                    chainBroken = true;
                }

                // 2) currentHash 체크: "로그에 적힌 previousHash" 기준으로 self-consistent 인지 확인
                //    (체인이 깨졌으면 이후 줄들은 어차피 연쇄 영향일 수 있으니, 원인/영향 구분에 도움 됨)
                try {
                    String expectedCurrent = HmacHasher.generateHmac(pl.message + pl.previousHash, secretKey);
                    if (!pl.currentHash.equals(expectedCurrent)) {
                        issues.add(Issue.currentHashMismatch(lineNo, expectedCurrent, pl.currentHash, line, chainBroken));
                        chainBroken = true;
                    }
                } catch (Exception e) {
                    issues.add(Issue.hashCalcError(lineNo, e.getMessage(), line, chainBroken));
                    chainBroken = true;
                }

                // 다음 줄 기대 prevHash 갱신은 "파일에 기록된 currentHash" 기준으로 진행
                // (그래야 이후 줄에서 '연쇄'가 어떻게 발생하는지 그대로 잡힘)
                expectedPrevHash = pl.currentHash;
                verified++;
            }
        }

        return new VerifyAllResult(issues.isEmpty(), verified, issues);
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

    public static class VerifyAllResult {
        public final boolean valid;
        public final int processedLines;   // 빈 줄 제외 처리한 라인 수
        public final List<Issue> issues;

        private VerifyAllResult(boolean valid, int processedLines, List<Issue> issues) {
            this.valid = valid;
            this.processedLines = processedLines;
            this.issues = issues;
        }

        public static VerifyAllResult fail(String reason) {
            List<Issue> list = new ArrayList<>();
            list.add(new Issue(0, IssueType.SYSTEM_ERROR, reason, null, null, null, false));
            return new VerifyAllResult(false, 0, list);
        }

        @Override
        public String toString() {
            if (valid) return "OK (processedLines=" + processedLines + ")";
            StringBuilder sb = new StringBuilder();
            sb.append("FAIL (processedLines=").append(processedLines).append(")\n");
            for (Issue i : issues) {
                sb.append(i).append("\n");
            }
            return sb.toString();
        }
    }

    public enum IssueType {
        PARSE_ERROR,
        TIMESTAMP_ROLLBACK,
        PREV_HASH_MISMATCH,
        CURRENT_HASH_MISMATCH,
        HASH_CALC_ERROR,
        SYSTEM_ERROR
    }

    public static class Issue {
        public final int line;
        public final IssueType type;
        public final String reason;
        public final String expected;
        public final String actual;
        public final String rawLine;
        public final boolean cascade; // true면 "이전 변조의 연쇄 영향"일 가능성이 큼

        private Issue(int line, IssueType type, String reason,
                      String expected, String actual, String rawLine, boolean cascade) {
            this.line = line;
            this.type = type;
            this.reason = reason;
            this.expected = expected;
            this.actual = actual;
            this.rawLine = rawLine;
            this.cascade = cascade;
        }

        static Issue parseError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.PARSE_ERROR, "로그 파싱 실패: " + msg, null, null, raw, cascade);
        }

        static Issue timestampRollback(int line, long prevTs, long curTs, String raw, boolean cascade) {
            return new Issue(line, IssueType.TIMESTAMP_ROLLBACK,
                    "타임스탬프 역행", "previousTimestamp=" + prevTs, "currentTimestamp=" + curTs, raw, cascade);
        }

        static Issue prevHashMismatch(int line, String expectedPrev, String actualPrev, String raw, boolean cascade) {
            return new Issue(line, IssueType.PREV_HASH_MISMATCH,
                    "previousHash 체인 불일치", expectedPrev, actualPrev, raw, cascade);
        }

        static Issue currentHashMismatch(int line, String expectedCur, String actualCur, String raw, boolean cascade) {
            return new Issue(line, IssueType.CURRENT_HASH_MISMATCH,
                    "currentHash 불일치", expectedCur, actualCur, raw, cascade);
        }

        static Issue hashCalcError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.HASH_CALC_ERROR,
                    "HMAC 계산 실패: " + msg, null, null, raw, cascade);
        }

        @Override
        public String toString() {
            return "[line " + line + "] " + type +
                    (cascade ? " (cascade)" : " (root)") +
                    " - " + reason +
                    (expected != null ? " | expected=" + expected : "") +
                    (actual != null ? " | actual=" + actual : "") +
                    (rawLine != null ? " | raw=" + rawLine : "");
        }
    }
}
