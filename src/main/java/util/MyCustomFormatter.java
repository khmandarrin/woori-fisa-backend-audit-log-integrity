package util;

import ch.qos.logback.classic.spi.ILoggingEvent;
import util.LogFormatter;

public class MyCustomFormatter implements LogFormatter {
    
    @Override
    public String format(ILoggingEvent event, String currentHash, String previousHash) {
        // 원하는 포맷으로 구현
        return String.format("%d | %s | %s | %s",
            event.getTimeStamp(),
            event.getFormattedMessage(),
            currentHash,
            previousHash);
    }

    @Override
    public String[] parse(String rawLine) {
        return rawLine.split("\\s\\|\\s", 4);
    }

    @Override
    public String extractMessage(String[] parts) {
        return parts[1];
    }

    @Override
    public String extractCurrentHash(String[] parts) {
        return parts[2];
    }

    @Override
    public String extractPrevHash(String[] parts) {
        return parts[3];
    }
}