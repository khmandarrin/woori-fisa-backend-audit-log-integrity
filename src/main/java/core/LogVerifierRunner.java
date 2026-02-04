package core;

import java.nio.file.Path;
import java.nio.file.Paths;

import verifier.LogVerifier;
import verifier.LogVerifier.VerifyResult;
import verifier.LogVerifier.Issue;

public class LogVerifierRunner {
    public static void main(String[] args) throws Exception {
        Path auditLogPath = Paths.get("audit.log");

        LogVerifier verifier = new LogVerifier();
        VerifyResult result = verifier.verify(auditLogPath);

        System.out.println(result);

        if (!result.valid) {
            System.out.println("---- 상세 ----");
            for (Issue issue : result.issues) {
                System.out.println("line    : " + issue.line);
                System.out.println("type    : " + issue.type);
                System.out.println("reason  : " + issue.reason);
                System.out.println("expected: " + issue.expected);
                System.out.println("actual  : " + issue.actual);
                System.out.println("cascade : " + issue.cascade);
                System.out.println("rawLine : " + issue.rawLine);
                System.out.println("------------------");
            }
        }
    }
}