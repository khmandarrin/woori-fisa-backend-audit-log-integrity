package util;

import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * 로그의 직렬화(Format) 및 역직렬화(Parse) 전략 인터페이스
 */
public interface LogFormatter {
	/**
	 * ILoggingEvent 객체를 포매팅해주는 함수
     * @param event Logback의 이벤트 객체
     * @param currentHash 이번에 계산된 해시
     * @param previousHash 직전 라인의 해시
     */
    String format(ILoggingEvent event, String currentHash, String previousHash);
    

    /**
     * 로그 파일을 지정된 포맷으로 파싱하는 함수
     * @param rawLine
     * @return
     */
    String[] parse(String rawLine);
}
