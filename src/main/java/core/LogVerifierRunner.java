package core;

import java.nio.file.Path;
import java.nio.file.Paths;

import verifier.LogVerifier;

public class LogVerifierRunner {
    public static void main(String[] args) throws Exception {
        Path auditLogPath = Paths.get("audit.log"); // 필요하면 경로 수정

        LogVerifier verifier = new LogVerifier();
        LogVerifier.VerifyResult result = verifier.verify(auditLogPath);

        System.out.println(result);

        if (!result.valid) {
            System.out.println("---- 상세 ----");
            System.out.println("line    : " + result.tamperedLine);
            System.out.println("reason  : " + result.reason);
            System.out.println("expected: " + result.expected);
            System.out.println("actual  : " + result.actual);
            System.out.println("rawLine : " + result.rawLine);
        }
    }
}
