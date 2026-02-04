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
    private final LogFormatter formatter;

    public LogVerifier() {
        this(new DefaultLogFormatter());
    }

    public LogVerifier(LogFormatter formatter) {
        this.formatter = formatter;
    }

    public VerifyResult verify(Path auditLogPath) throws IOException {
        if (auditLogPath == null) {
            return VerifyResult.fail("auditLogPath가 null 입니다.");
        }
        if (!Files.exists(auditLogPath)) {
            return VerifyResult.fail("파일이 존재하지 않습니다: " + auditLogPath);
        }

        final String secretKey = KeyManager.getSecretKey();
        int lineNo = 0;
        int verified = 0;
        String expectedPrevHash = GENESIS_PREV_HASH;
        boolean chainBroken = false;
        List<Issue> issues = new ArrayList<>();

        try (BufferedReader br = Files.newBufferedReader(auditLogPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lineNo++;
                if (line.trim().isEmpty()) continue;

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

                if (!previousHash.equals(expectedPrevHash)) {
                    issues.add(Issue.prevHashMismatch(lineNo, expectedPrevHash, previousHash, line, chainBroken));
                    chainBroken = true;
                }

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

                expectedPrevHash = currentHash;
                verified++;
            }
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

        public static VerifyResult fail(String reason) {
            List<Issue> list = new ArrayList<>();
            list.add(new Issue(0, IssueType.SYSTEM_ERROR, reason, null, null, null, false));
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

        static Issue parseError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.PARSE_ERROR, "로그 파싱 실패: " + msg, null, null, raw, cascade);
        }

        static Issue prevHashMismatch(int line, String expectedPrev, String actualPrev, String raw, boolean cascade) {
            return new Issue(line, IssueType.PREV_HASH_MISMATCH, "previousHash 체인 불일치", expectedPrev, actualPrev, raw, cascade);
        }

        static Issue currentHashMismatch(int line, String expectedCur, String actualCur, String raw, boolean cascade) {
            return new Issue(line, IssueType.CURRENT_HASH_MISMATCH, "currentHash 불일치", expectedCur, actualCur, raw, cascade);
        }

        static Issue hashCalcError(int line, String msg, String raw, boolean cascade) {
            return new Issue(line, IssueType.HASH_CALC_ERROR, "HMAC 계산 실패: " + msg, null, null, raw, cascade);
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