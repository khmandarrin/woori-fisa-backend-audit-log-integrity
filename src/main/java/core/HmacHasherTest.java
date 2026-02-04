package core;

import util.HmacHasher;

public class HmacHasherTest {
	public static void main(String[] args) throws Exception {
	    String secretKey = "my-finance-secret-key"; // 실제론 외부 주입
	    String prevHash = "0000000000000000"; // 초기값 (First Seed)

	    String[] logs = {"사용자 A 로그인", "사용자 A가 B에게 100만원 송금", "사용자 A 로그아웃"};

	    for (String log : logs) {
	        // [현재 로그 + 이전 해시]를 합쳐서 새 해시 생성
	        String currentHash = HmacHasher.generateHmac(log + prevHash, secretKey);
	        
	        System.out.println("로그 내용: " + log);
	        System.out.println("계산된 HMAC: " + currentHash);
	        System.out.println("---------------------------------------");
	        
	        // 현재 해시가 다음 로그의 '이전 해시'가 됨
	        prevHash = currentHash;
	    }
	}
}
