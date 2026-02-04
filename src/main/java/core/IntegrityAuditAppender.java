package core;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import util.DefaultLogFormatter;
import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

public class IntegrityAuditAppender extends UnsynchronizedAppenderBase<ILoggingEvent>{
	private String previousHash = "INIT_SEED_0000"; // 첫 번째 로그를 위한 초기값
    private String logFileName = "audit.log";      // 로그 파일명

    
    private LogFormatter formatter = new DefaultLogFormatter();

    // 사용자가 만든 Formatter 클래스명을 받아서 설정 파일에서 불러오기 위한 메서드
    public void setFormatterClass(String className) {
        try {
            Class<?> clazz = Class.forName(className);
            this.formatter = (LogFormatter) clazz.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            addError("Formatter 생성 실패: " + className, e);
        }
    }
    
    // 로그 파일 이름을 받아서 설정 파일에서 설정하기 위한 메서드
    public void setLogFileName(String logFileName) {
        this.logFileName = logFileName;
    }
    
    @Override
    protected void append(ILoggingEvent eventObject) {
        String message = eventObject.getFormattedMessage();
        String secretKey = KeyManager.getSecretKey();

        try {
            // 1. [현재 메시지 + 이전 해시]로 현재 해시 생성
            String currentHash = HmacHasher.generateHmac(message + previousHash, secretKey);

            // 2. 로그 포맷팅 
            String logLine = formatter.format(eventObject, currentHash, previousHash);

            // 3. 파일에 쓰기
            writeLogToFile(logLine);

            // 4. 현재 해시를 다음 로그의 '이전 해시'로 업데이트 (체이닝)
            this.previousHash = currentHash;

        } catch (Exception e) {
            addError("로그 중 오류 발생: " + message, e);
        }
    }

    private void writeLogToFile(String logLine) {
        try (PrintWriter out = new PrintWriter(new FileWriter(logFileName, true))) {
            out.println(logLine);
        } catch (IOException e) {
            addError("파일 쓰기 오류", e);
        }
    }
}
