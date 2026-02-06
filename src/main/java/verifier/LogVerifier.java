package verifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import util.DefaultLogFormatter;
import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

public class LogVerifier {

    private static final String GENESIS_PREV_HASH = "INIT_SEED_0000";
    private static final String AUDIT_HEAD_FILENAME = "audit.head";
    private final LogFormatter formatter;

    /**
     * 기본 LogFormatter를 사용하는 LogVerifier를 생성한다.
     */
    public LogVerifier() {
        this(new DefaultLogFormatter());
    }

    /**
     * 지정된 LogFormatter를 사용하는 LogVerifier를 생성한다.
     *
     * @param formatter 로그 파싱 및 필드 추출에 사용할 포매터
     */
    public LogVerifier(LogFormatter formatter) {
        this.formatter = formatter;
    }

    /**
     * 감사 로그 파일의 무결성을 검증한다.
     *
     * @param auditLogPath 검증할 감사 로그 파일 경로
     * @return 검증 결과를 담은 VerifyResult 객체
     * @throws IOException 파일 읽기 중 I/O 오류 발생 시
     */
    public VerifyResult verify(Path auditLogPath) throws IOException {
        // 1. 입력 유효성 검사
        if (auditLogPath == null) {
            return VerifyResult.fail("auditLogPath가 null 입니다.");
        }
        if (!Files.exists(auditLogPath)) {
            return VerifyResult.fail("파일이 존재하지 않습니다: " + auditLogPath);
        }

        final String secretKey = KeyManager.getSecretKey();
        int lineNo = 0;
        int verified = 0;
        String expectedPrevHash = GENESIS_PREV_HASH;  // 첫 로그는 GENESIS 해시와 연결되어야 함
        boolean chainBroken = false;  // 체인이 한 번 끊기면 이후 오류는 cascade로 표시
        List<Issue> issues = new ArrayList<>();
        String lastFileHead = null;

        // 2. 로그 파일 순회하며 각 라인 검증
        try (BufferedReader br = Files.newBufferedReader(auditLogPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;
                if (line.trim().isEmpty()) continue;

                // 2-1. 로그 라인 파싱
                String[] parts;
                try {
                    parts = formatter.parse(line);
                } catch (IllegalArgumentException e) {
                    issues.add(Issue.parseError(lineNo, e.getMessage(), line, chainBroken));
                    chainBroken = true;
                    continue;
                }

                String message = formatter.extractMessage(parts);
                String currentHash = formatter.extractCurrentHash(parts);
                String previousHash = formatter.extractPrevHash(parts);

                lastFileHead = currentHash;

                // 2-2. 체인 연결 검증: 현재 로그의 prevHash가 이전 로그의 currentHash와 일치해야 함
                if (!previousHash.equals(expectedPrevHash)) {
                    issues.add(Issue.prevHashMismatch(lineNo, expectedPrevHash, previousHash, line, chainBroken));
                    chainBroken = true;
                }

                // 2-3. 해시 무결성 검증: currentHash == HMAC(message + prevHash, secretKey)
                try {
                    String calculatedHash = HmacHasher.generateHmac(message + previousHash, secretKey);
                    if (!currentHash.equals(calculatedHash)) {
                        issues.add(Issue.currentHashMismatch(lineNo, calculatedHash, currentHash, line, chainBroken));
                        chainBroken = true;
                    }
                } catch (Exception e) {
                    issues.add(Issue.hashCalcError(lineNo, e.getMessage(), line, chainBroken));
                    chainBroken = true;
                }

                // 다음 로그 검증을 위해 expectedPrevHash 갱신
                expectedPrevHash = currentHash;
                verified++;
            }
        }

        // 3. 끝 삭제(truncation) 탐지: audit.head 파일과 마지막 로그 해시 비교
        Path headPath = auditLogPath.resolveSibling(AUDIT_HEAD_FILENAME);
        String storedHead = null;
        if (Files.exists(headPath)) {
            storedHead = Files.readString(headPath, StandardCharsets.UTF_8).trim();
            if (storedHead.isEmpty()) storedHead = null;
        }

        // head 파일에 저장된 해시와 실제 마지막 로그 해시가 다르면 끝 삭제 의심
        if (storedHead != null && (lastFileHead == null || !storedHead.equals(lastFileHead))) {
            issues.add(Issue.tailTruncation(Math.max(1, lineNo), storedHead, lastFileHead));
        }

        return new VerifyResult(issues.isEmpty(), verified, issues);
    }

    public static class VerifyResult {
        public final boolean valid;
        public final int processedLines;
        public final List<Issue> issues;

        private VerifyResult(boolean valid, int processedLines, List<Issue> issues) {
            this.valid = valid;
            this.processedLines = processedLines;
            this.issues = issues;
        }

        /**
         * 즉시 실패 결과를 생성한다.
         *
         * @param reason 실패 사유
         * @return 실패 상태의 VerifyResult
         */
        public static VerifyResult fail(String reason) {
            List<Issue> list = new ArrayList<>();
            list.add(Issue.systemError(reason));
            return new VerifyResult(false, 0, list);
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
        PREV_HASH_MISMATCH,
        CURRENT_HASH_MISMATCH,
        HASH_CALC_ERROR,
        TAIL_TRUNCATION,   // ✅ 추가
        SYSTEM_ERROR
    }

    public static class Issue {
        public final int line;
        public final IssueType type;
        public final String reason;
        public final String expected;
        public final String actual;
        public final String rawLine;
        public final boolean cascade;

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

        /**
         * 파싱 오류 Issue를 생성한다.
         *
         * @param line 라인 번호
         * @param msg 오류 메시지
         * @param raw 원본 로그 라인
         * @param cascade 연쇄 오류 여부
         * @return 파싱 오류 Issue
         */
        static Issue parseError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.PARSE_ERROR, "로그 파싱 실패: " + msg, null, null, raw, cascade);
        }

        /**
         * previousHash 불일치 Issue를 생성한다.
         *
         * @param line 라인 번호
         * @param expectedPrev 기대한 previousHash
         * @param actualPrev 실제 previousHash
         * @param raw 원본 로그 라인
         * @param cascade 연쇄 오류 여부
         * @return previousHash 불일치 Issue
         */
        static Issue prevHashMismatch(int line, String expectedPrev, String actualPrev, String raw, boolean cascade) {
            return new Issue(line, IssueType.PREV_HASH_MISMATCH, "previousHash 체인 불일치", expectedPrev, actualPrev, raw, cascade);
        }

        /**
         * currentHash 불일치 Issue를 생성한다.
         *
         * @param line 라인 번호
         * @param expectedCur 기대한 currentHash
         * @param actualCur 실제 currentHash
         * @param raw 원본 로그 라인
         * @param cascade 연쇄 오류 여부
         * @return currentHash 불일치 Issue
         */
        static Issue currentHashMismatch(int line, String expectedCur, String actualCur, String raw, boolean cascade) {
            return new Issue(line, IssueType.CURRENT_HASH_MISMATCH, "currentHash 불일치", expectedCur, actualCur, raw, cascade);
        }

        /**
         * HMAC 계산 오류 Issue를 생성한다.
         *
         * @param line 라인 번호
         * @param msg 오류 메시지
         * @param raw 원본 로그 라인
         * @param cascade 연쇄 오류 여부
         * @return HMAC 계산 오류 Issue
         */
        static Issue hashCalcError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.HASH_CALC_ERROR, "HMAC 계산 실패: " + msg, null, null, raw, cascade);
        }

        /**
         * 끝 로그 삭제 의심 Issue를 생성한다.
         *
         * @param line 라인 번호
         * @param storedHead audit.head에 저장된 해시
         * @param fileLastHead 파일의 마지막 해시
         * @return 끝 삭제 의심 Issue
         */
        static Issue tailTruncation(int line, String storedHead, String fileLastHead) {
            return new Issue(
                    line,
                    IssueType.TAIL_TRUNCATION,
                    "파일 끝 로그 삭제/롤백 의심(head 불일치)",
                    "storedHead=" + storedHead,
                    "fileLastHead=" + fileLastHead,
                    null,
                    false
            );
        }

        /**
         * 시스템 오류 Issue를 생성한다.
         *
         * @param reason 오류 사유
         * @return 시스템 오류 Issue
         */
        static Issue systemError(String reason) {
            return new Issue(0, IssueType.SYSTEM_ERROR, reason, null, null, null, false);
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