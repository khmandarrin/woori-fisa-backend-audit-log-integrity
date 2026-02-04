package core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LogTest {
	private static final Logger logger = LoggerFactory.getLogger(LogTest.class);

    public static void main(String[] args) {
        logger.info("첫 번째 감사 로그: 관리자 로그인");
        logger.info("두 번째 감사 로그: 계좌 이체 실행(100만원)");
        logger.info("세 번째 감사 로그: 관리자 로그아웃");
        
        System.out.println("로그 생성이 완료되었습니다. audit.log 파일을 확인하세요.");
    }
}
