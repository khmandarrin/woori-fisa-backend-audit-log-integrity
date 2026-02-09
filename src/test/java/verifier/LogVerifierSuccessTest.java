package verifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mockStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;

import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

/**
 * 그룹 2: 정상 시나리오 테스트
 *
 * <p>
 * 모든 검증을 정상 통과하는 케이스들을 검증한다.
 * </p>
 * <p>
 * 해시 체인이 올바르게 연결되고, 모든 해시값이 일치하는 상황을 테스트한다.
 * </p>
 *
 * <h2>다루는 Issue 타입</h2>
 * <ul>
 * <li>없음 - 모든 검증 통과 시 issues 리스트가 비어있음</li>
 * </ul>
 *
 * <h2>검증 포인트</h2>
 * <ul>
 * <li>valid = true</li>
 * <li>processedLines = 처리된 로그 수</li>
 * <li>issues.isEmpty() = true</li>
 * </ul>
 *
 * <h2>사용하는 Mock 객체</h2>
 * <ul>
 * <li>{@link LogFormatter} - 로그 파싱 및 필드 추출</li>
 * <li>{@code MockedStatic<KeyManager>} - 시크릿 키 반환</li>
 * <li>{@code MockedStatic<HmacHasher>} - HMAC 해시 생성</li>
 * </ul>
 */

@ExtendWith(MockitoExtension.class)
class LogVerifierSuccessTest {

	private static Path tempDir;
	private static final String SECRET_KEY = "TEST_SECRET";

	@Mock
	private LogFormatter mockFormatter;

	@BeforeAll
	static void setUpAll() throws IOException {
		// 테스트용 임시 디렉토리 생성
		tempDir = Files.createTempDirectory("log-verifier-test");
	}

	@AfterAll
	static void tearDownAll() throws IOException {
		// 생성된 임시 파일 및 디렉토리 삭제
		if (Files.exists(tempDir)) {
			Files.walk(tempDir).sorted((a, b) -> -a.compareTo(b)).forEach(p -> {
				try {
					Files.delete(p);
				} catch (Exception ignored) {
				}
			});
		}
	}

	/**
	 * 정상적인 단일 로그 검증 테스트.
	 *
	 * <p>
	 * 시나리오: 로그 파일에 1개의 정상 로그가 존재하고, 해시 체인이 올바른 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>formatter.parse() 성공 → 6개 필드 배열 반환</li>
	 * <li>prevHash == GENESIS_PREV_HASH ("INIT_SEED_0000") → 체인 연결 정상</li>
	 * <li>currentHash == HmacHasher.generateHmac(message + prevHash) → 해시 무결성
	 * 정상</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=1, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("단일 로그 검증: GENESIS와 연결된 1개의 로그가 정상인 경우")
	void verify_SingleValidLog_ReturnsSuccess() throws Exception {
		
		// given
		Path logFile = tempDir.resolve("single.log");
		String rawLine = "RAW_LOG_LINE_1";
		Files.write(logFile, List.of(rawLine), StandardCharsets.UTF_8);

		// 모킹에 사용할 기대값들
		String message = "LOGIN user=kim";
		String prevHash = "INIT_SEED_0000";
		String currentHash = "HASH1";
		String[] parsedResult = {"parsed_0"}; // 고유한 파싱 결과 객체
		
		// 단일 로그의 해시와 audit.head를 일치시켜 Truncation 이슈 방지
        Files.writeString(logFile.resolveSibling("audit.head"), currentHash);

        // Mocking: Formatter 동작 정의
        given(mockFormatter.parse(rawLine)).willReturn(parsedResult);
        given(mockFormatter.extractMessage(parsedResult)).willReturn(message);
        given(mockFormatter.extractPrevHash(parsedResult)).willReturn(prevHash);
        given(mockFormatter.extractCurrentHash(parsedResult)).willReturn(currentHash);

		try (MockedStatic<KeyManager> keyManagerMock = mockStatic(KeyManager.class);
				MockedStatic<HmacHasher> hmacMock = mockStatic(HmacHasher.class)) {
			// 전역 설정 모킹
			keyManagerMock.when(util.KeyManager::getSecretKey).thenReturn(SECRET_KEY);
			// 해시 계산 결과 모킹: HMAC(메시지 + 이전해시, 키) -> 현재해시
			hmacMock.when(() -> util.HmacHasher.generateHmac(message + prevHash, SECRET_KEY)).thenReturn(currentHash);

			LogVerifier verifier = new LogVerifier(mockFormatter);
			LogVerifier.VerifyResult result = verifier.verify(logFile);

			// then
			assertTrue(result.valid); // 검증 결과는 true 여야 함
			assertEquals(1, result.processedLines); // 처리된 라인 수는 1이어야 함
			assertTrue(result.issues.isEmpty()); // 발견된 이슈가 없어야 함
		}
	}

	/**
	 * 정상적인 다중 로그 체인 검증 테스트.
	 *
	 * <p>
	 * 시나리오: 로그 파일에 N개의 로그가 존재하고, 모든 해시 체인이 올바르게 연결된 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름 (각 로그마다 반복):
	 * </p>
	 * <ol>
	 * <li>로그1: prevHash == GENESIS → currentHash1 생성</li>
	 * <li>로그2: prevHash == currentHash1 → currentHash2 생성</li>
	 * <li>로그N: prevHash == currentHash(N-1) → currentHashN 생성</li>
	 * </ol>
	 *
	 * <p>
	 * 체인 구조:
	 * </p>
	 * 
	 * <pre>
	 * GENESIS → 로그1(hash1) → 로그2(hash2) → 로그3(hash3) → ...
	 * </pre>
	 *
	 * <p>
	 * 추가되는 Issue: 없음
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=N, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("다중 로그 검증: N개의 로그가 해시 체인으로 완벽히 연결된 경우")
	void verify_MultipleValidLogs_ReturnsSuccess() throws Exception {

		// given: N개의 로그 데이터 준비
		Path logFile = tempDir.resolve("multiple.log");
		int N = 3;
		List<String> rawLines = List.of("RAW_1", "RAW_2", "RAW_3");
		Files.write(logFile, rawLines, StandardCharsets.UTF_8);

		String[] messages = { "MSG1", "MSG2", "MSG3" };
		String[] hashes = { "HASH1", "HASH2", "HASH3" };
		String genesisHash = "INIT_SEED_0000";

		// 각 라인별 Formatter와 HMAC 계산 로직 모킹
		try (MockedStatic<KeyManager> keyManagerMock = mockStatic(KeyManager.class);
				MockedStatic<HmacHasher> hmacMock = mockStatic(HmacHasher.class)) {

			keyManagerMock.when(KeyManager::getSecretKey).thenReturn(SECRET_KEY);
			
			// 파일 끝 삭제(Truncation) 여부를 검증하기 위해, 마지막 로그의 해시값을 별도 head 파일에 기록
			Files.writeString(logFile.resolveSibling("audit.head"), hashes[N - 1]);

			for (int i = 0; i < N; i++) {
				String raw = rawLines.get(i);
				String prev = (i == 0) ? genesisHash : hashes[i - 1];
				String curr = hashes[i];
				String msg = messages[i];

				// 각 라인마다 Mockito가 식별할 수 있는 고유한 배열 생성
                String[] parsed = {"parsed_" + i};
                
				// Formatter 동작 정의
                given(mockFormatter.parse(raw)).willReturn(parsed);
                given(mockFormatter.extractMessage(parsed)).willReturn(msg);
                given(mockFormatter.extractPrevHash(parsed)).willReturn(prev);
                given(mockFormatter.extractCurrentHash(parsed)).willReturn(curr);

				// Static 메서드(HMAC 생성) 모킹
				hmacMock.when(() -> HmacHasher.generateHmac(msg + prev, SECRET_KEY)).thenReturn(curr);
			}
			
			// when
			LogVerifier verifier = new LogVerifier(mockFormatter);
			LogVerifier.VerifyResult result = verifier.verify(logFile);

			// then
			assertTrue(result.valid); // 모든 체인이 정상이면 true 여야 함
			assertEquals(N, result.processedLines); // 처리된 라인 수는 N이어야 함
			assertTrue(result.issues.isEmpty()); // 이슈가 존재하지 않아야 함
		}
	}

}
