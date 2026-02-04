package core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public class LogTest {
	private static final Logger logger = LoggerFactory.getLogger(LogTest.class);

    public static void main(String[] args) {
    	
        // MDC 설정
        MDC.put("userId", "admin001");
        MDC.put("clientIp", "192.168.1.100");
        
        // 로그인
        logger.info("관리자 로그인");

        // 조회
        logger.info("계좌조회: 계좌번호=110-123-456");

        // 이체
        logger.info("계좌이체: 금액=1000000원, 출금=110-123-456, 입금=220-456-789");

        // 로그아웃
        logger.info("관리자 로그아웃");
        
        System.out.println("로그 생성이 완료되었습니다. audit.log 파일을 확인하세요.");
    }
}
