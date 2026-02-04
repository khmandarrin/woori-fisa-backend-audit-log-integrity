package core;

import java.nio.file.Paths;

import verifier.LogVerifier;

public class LogVerifierRunner {
    public static void main(String[] args) throws Exception {
    	
        LogVerifier verifier = new LogVerifier();
        LogVerifier.VerifyAllResult all = verifier.verifyAll(Paths.get("audit.log"));

        System.out.println(all); // 전체 리스트 출력(원하면 제거 가능)

        if (!all.valid) {
            System.out.println("---- 상세(전체) ----");
            for (LogVerifier.Issue issue : all.issues) {
                System.out.println("line    : " + issue.line + (issue.cascade ? " (cascade)" : " (root)"));
                System.out.println("reason  : " + issue.reason);
                System.out.println("expected: " + issue.expected);
                System.out.println("actual  : " + issue.actual);
                System.out.println("rawLine : " + issue.rawLine);
                System.out.println();
            }
        }
    }
}
