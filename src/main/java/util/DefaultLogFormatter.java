package util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import ch.qos.logback.classic.spi.ILoggingEvent;

public class DefaultLogFormatter implements LogFormatter{
	private static final String DELIMITER = " | ";
    private static final String REGEX_DELIMITER = "\\s\\|\\s";

    private String timeZone = "Asia/Seoul";
    private String datePattern = "yyyy-MM-dd HH:mm:ss";
    
    @Override
    public String format(ILoggingEvent event, String currentHash, String previousHash) {
        String formattedTime = Instant.ofEpochMilli(event.getTimeStamp())
                .atZone(ZoneId.of(timeZone))
                .format(DateTimeFormatter.ofPattern(datePattern));
        
        // MDC에서 userId, clientIp 꺼내기
        String userId = event.getMDCPropertyMap().getOrDefault("userId", "SYSTEM");
        String clientIp = event.getMDCPropertyMap().getOrDefault("clientIp", "N/A");
        
        // ILoggingEvent에서 직접 타임스탬프와 메시지를 가져옴
        return new StringBuilder()
            .append(formattedTime).append(DELIMITER)
            .append(userId).append(DELIMITER)
            .append(clientIp).append(DELIMITER)
            .append(event.getFormattedMessage()).append(DELIMITER)
            .append(currentHash).append(DELIMITER)
            .append(previousHash)
            .toString();
    }

    @Override
    public String[] parse(String rawLine) {
        if (rawLine == null || rawLine.trim().isEmpty()) {
            throw new IllegalArgumentException("로그 라인이 비어있습니다.");
        }
        
        // 정규표현식을 사용하여 " | " 구분자로 분리
        String[] parts = rawLine.split(REGEX_DELIMITER, 6);
        if (parts.length != 6) {
            throw new IllegalArgumentException("로그 포맷이 일치하지 않습니다. (필드 개수 부족)");
        }
        return parts;
    }
    
	@Override
	public String extractMessage(String[] parts) {
		return parts[3];
	}

	@Override
	public String extractPrevHash(String[] parts) {
		return parts[5];
	}

	@Override
	public String extractCurrentHash(String[] parts) {
		return parts[4];
	}
    
    public void setTimeZone(String timeZone) {
        this.timeZone = timeZone;
    }

    public void setDatePattern(String datePattern) {
        this.datePattern = datePattern;
    }
}
