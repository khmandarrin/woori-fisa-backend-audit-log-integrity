package verifier;

import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 그룹 4: 무결성/체인 깨짐/복합 이슈 테스트
 *
 * <p>
 * 예외는 발생하지 않지만 해시 값 비교 결과 불일치가 발생하는 케이스들을 검증한다.
 * </p>
 * <p>
 * 로그 변조, 삭제, 순서 변경 등 보안 위협 상황을 탐지하는 로직을 테스트한다.
 * </p>
 *
 * <h2>다루는 Issue 타입</h2>
 * <ul>
 * <li>{@link verifier.LogVerifier.IssueType#PREV_HASH_MISMATCH} - 현재 로그의
 * prevHash가 이전 로그의 currentHash와 불일치 (중간 로그 삭제/순서 변경 의심)</li>
 * <li>{@link verifier.LogVerifier.IssueType#CURRENT_HASH_MISMATCH} -
 * currentHash가 HMAC(message + prevHash)와 불일치 (로그 내용 변조 의심)</li>
 * <li>{@link verifier.LogVerifier.IssueType#TAIL_TRUNCATION} - audit.head 파일의
 * 해시와 로그 파일 마지막 해시 불일치 (끝 로그 삭제/롤백 의심)</li>
 * </ul>
 *
 * <h2>cascade 플래그</h2>
 * <ul>
 * <li>cascade=false: 최초 발생 오류 (root cause)</li>
 * <li>cascade=true: 이전 오류로 인해 파생된 연쇄 오류</li>
 * </ul>
 *
 * <h2>사용하는 Mock 객체</h2>
 * <ul>
 * <li>{@link LogFormatter} - 로그 파싱 및 필드 추출</li>
 * <li>{@code MockedStatic<KeyManager>} - 시크릿 키 반환</li>
 * <li>{@code MockedStatic<HmacHasher>} - HMAC 해시 생성 (불일치 시뮬레이션)</li>
 * </ul>
 */
class LogVerifierIntegrityTest {

	private static Path tempDir;

	private LogFormatter mockFormatter;
	private MockedStatic<KeyManager> mockKeyManager;
	private MockedStatic<HmacHasher> mockHmacHasher;

	private String secretKey;
	private String genesisHash;

	@BeforeAll
	static void setUpAll() throws IOException {
		tempDir = Files.createTempDirectory("log-verifier-integrity-test");
	}

	@BeforeEach
	void setUp() {
		mockFormatter = Mockito.mock(LogFormatter.class);
		mockKeyManager = Mockito.mockStatic(KeyManager.class);
		mockHmacHasher = Mockito.mockStatic(HmacHasher.class);

		secretKey = "test-secret-key";
		genesisHash = "INIT_SEED_0000";
		mockKeyManager.when(KeyManager::getSecretKey).thenReturn(secretKey);
	}

	@AfterEach
	void tearDown() throws Exception {
		if (mockKeyManager != null) {
			mockKeyManager.close();
		}
		if (mockHmacHasher != null) {
			mockHmacHasher.close();
		}
	}

	@AfterAll
	static void tearDownAll() throws IOException {
		Files.walk(tempDir).sorted((a, b) -> -a.compareTo(b)).forEach(p -> {
			try {
				Files.delete(p);
			} catch (Exception ignored) {
			}
		});
	}

	/**
	 * previousHash 불일치 시 PREV_HASH_MISMATCH 이슈 발생 테스트.
	 *
	 * <p>
	 * 시나리오: 두 번째 로그의 prevHash가 첫 번째 로그의 currentHash와 다른 경우
	 * </p>
	 *
	 * <p>
	 * 발생 위치: {@code LogVerifier.verify()} 내 체인 검증 블록 (line 85-88)
	 * </p>
	 * 
	 * <pre>
	 * if (!previousHash.equals(expectedPrevHash)) {
	 * 	issues.add(Issue.prevHashMismatch(lineNo, expectedPrevHash, previousHash, line, chainBroken));
	 * 	chainBroken = true;
	 * }
	 * </pre>
	 *
	 * <p>
	 * 추가되는 Issue:
	 * </p>
	 * <ul>
	 * <li>type: {@code PREV_HASH_MISMATCH}</li>
	 * <li>reason: "previousHash 체인 불일치"</li>
	 * <li>expected: 이전 로그의 currentHash (또는 GENESIS)</li>
	 * <li>actual: 현재 로그에 기록된 prevHash</li>
	 * <li>rawLine: 체인이 끊긴 로그 라인</li>
	 * </ul>
	 *
	 * <p>
	 * 탐지 가능한 공격:
	 * </p>
	 * <ul>
	 * <li>중간 로그 삭제</li>
	 * <li>로그 순서 변경</li>
	 * <li>로그 삽입 (새 로그가 기존 체인과 연결되지 않음)</li>
	 * </ul>
	 *
	 * <p>
	 * 기대 결과: valid=false, issues에 PREV_HASH_MISMATCH 포함, expected/actual 값 검증
	 * </p>
	 */
	@Test
	@DisplayName("현재 로그의 prevHash가 이전 로그의 currentHash와 다르면 PREV_HASH_MISMATCH 이슈 발생 (중간 로그 삭제/순서 변경 탐지)")
	void verify_PrevHashMismatch_ReturnsPrevHashMismatchError() throws IOException {
		// 1. 전제 조건 설정 (Given)
		// mockKeyManager는 setUp()에서 설정됨

		// 로그 데이터 정의
		LogData log1 = new LogData(1, "User logged in", genesisHash, "HASH_1");
		LogData log2 = new LogData(2, "Sensitive access", "INVALID_PREV", "HASH_2");

		// 포매터 및 해시 동작 일괄 설정 (Helper 사용)
		setupMockBehavior(log1, secretKey);
		setupMockBehavior(log2, secretKey);

		// 테스트 파일 생성
		Path logFile = createTempLogFile(log1.raw, log2.raw);
		createTempHeadFile(log2.currentHash); // 마지막 로그 해시를 head로 설정

		// 2. 실행 (When)
		LogVerifier verifier = new LogVerifier(mockFormatter);
		LogVerifier.VerifyResult result = verifier.verify(logFile);

		// 3. 검증 (Then)
		assertAll("체인 단절 검증", () -> assertFalse(result.valid, "검증 결과는 false여야 함"),
				() -> assertEquals(1, result.issues.size(), "이슈는 정확히 1개여야 함"), () -> {
					LogVerifier.Issue issue = result.issues.get(0);
					assertEquals(LogVerifier.IssueType.PREV_HASH_MISMATCH, issue.type);
					assertEquals(2, issue.line, "2번 라인에서 오류 발생");
					assertEquals(log1.currentHash, issue.expected, "기대값은 1번 로그의 currentHash");
					assertEquals(log2.prevHash, issue.actual, "실제값은 2번 로그의 잘못된 prevHash");
				});
	}

	/**
	 * currentHash 불일치 시 CURRENT_HASH_MISMATCH 이슈 발생 테스트.
	 *
	 * <p>
	 * 시나리오: 로그에 기록된 currentHash가 HMAC(message + prevHash) 계산 결과와 다른 경우
	 * </p>
	 *
	 * <p>
	 * 발생 위치: {@code LogVerifier.verify()} 내 해시 무결성 검증 블록 (line 91-97)
	 * </p>
	 * 
	 * <pre>
	 * String calculatedHash = HmacHasher.generateHmac(message + previousHash, secretKey);
	 * if (!currentHash.equals(calculatedHash)) {
	 * 	issues.add(Issue.currentHashMismatch(lineNo, calculatedHash, currentHash, line, chainBroken));
	 * 	chainBroken = true;
	 * }
	 * </pre>
	 *
	 * <p>
	 * 추가되는 Issue:
	 * </p>
	 * <ul>
	 * <li>type: {@code CURRENT_HASH_MISMATCH}</li>
	 * <li>reason: "currentHash 불일치"</li>
	 * <li>expected: HMAC으로 계산한 올바른 해시값</li>
	 * <li>actual: 로그에 기록된 (변조된) 해시값</li>
	 * <li>rawLine: 변조된 로그 라인</li>
	 * </ul>
	 *
	 * <p>
	 * 탐지 가능한 공격:
	 * </p>
	 * <ul>
	 * <li>로그 메시지 내용 변조</li>
	 * <li>해시값 직접 위조</li>
	 * <li>타임스탬프/사용자 정보 변조</li>
	 * </ul>
	 *
	 * <p>
	 * 기대 결과: valid=false, issues에 CURRENT_HASH_MISMATCH 포함, expected에 계산된 해시,
	 * actual에 변조된 해시
	 * </p>
	 * 
	 * @throws IOException
	 */
	@Test
	@DisplayName("로그의 currentHash가 HMAC(message+prevHash) 계산 결과와 다르면 CURRENT_HASH_MISMATCH 이슈 발생 (로그 변조 탐지)")
	void verify_CurrentHashMismatch_ReturnsCurrentHashMismatchError() throws IOException {
		// 1. Given

		String correctHash = "CORRECT_HMAC_RESULT";
		String tamperedHash = "TAMPERED_HASH_IN_LOG";

		// 로그 데이터 정의 (기록된 해시는 tamperedHash 지만, 계산 결과는 correctHash 가 나오도록 모킹할 것임)
		LogData log1 = new LogData(1, "User login", genesisHash, tamperedHash);

		// 모킹 설정
		String[] parts = log1.toParts();
		when(mockFormatter.parse(log1.raw)).thenReturn(parts);
		when(mockFormatter.extractMessage(parts)).thenReturn(log1.msg);
		when(mockFormatter.extractPrevHash(parts)).thenReturn(log1.prevHash);
		when(mockFormatter.extractCurrentHash(parts)).thenReturn(log1.currentHash);

		// HMAC 계산 시 로그에 적힌 tamperedHash가 아닌 correctHash를 반환하도록 시뮬레이션
		mockHmacHasher.when(() -> HmacHasher.generateHmac(log1.msg + log1.prevHash, secretKey)).thenReturn(correctHash);

		Path logFile = createTempLogFile(log1.raw);
		createTempHeadFile(tamperedHash);

		// 2. When
		LogVerifier verifier = new LogVerifier(mockFormatter);
		LogVerifier.VerifyResult result = verifier.verify(logFile);

		// 3. Then
		assertAll("현재 해시 불일치 검증", () -> assertFalse(result.valid), () -> {
			LogVerifier.Issue issue = result.issues.get(0);
			assertEquals(LogVerifier.IssueType.CURRENT_HASH_MISMATCH, issue.type);
			assertEquals(correctHash, issue.expected, "기대값은 HMAC으로 계산된 올바른 해시");
			assertEquals(tamperedHash, issue.actual, "실제값은 로그에 기록되어 있던 변조된 해시");
		});
	}

	/**
	 * 연쇄 오류(cascading) 발생 시 cascade 플래그 테스트.
	 *
	 * <p>
	 * 시나리오: 첫 번째 로그에서 오류 발생 후, 이후 로그들에서 연쇄적으로 오류 발생
	 * </p>
	 *
	 * <p>
	 * cascade 플래그 동작:
	 * </p>
	 * <ul>
	 * <li>첫 번째 오류: chainBroken=false 상태에서 발생 → cascade=false (root cause)</li>
	 * <li>이후 오류: chainBroken=true 상태에서 발생 → cascade=true (연쇄 오류)</li>
	 * </ul>
	 *
	 * <p>
	 * 예시 흐름:
	 * </p>
	 * 
	 * <pre>
	 * 로그1: currentHash 변조됨 → CURRENT_HASH_MISMATCH (cascade=false)
	 *        chainBroken = true 설정
	 * 로그2: prevHash != 로그1의 currentHash → PREV_HASH_MISMATCH (cascade=true)
	 * 로그3: 정상이지만 체인이 이미 끊김 → PREV_HASH_MISMATCH (cascade=true)
	 * </pre>
	 *
	 * <p>
	 * cascade 플래그의 의미:
	 * </p>
	 * <ul>
	 * <li>cascade=false: 실제 문제 원인이 되는 로그 (조사 우선순위 높음)</li>
	 * <li>cascade=true: 이전 오류의 영향으로 발생한 오류 (원인 해결 시 자동 해결)</li>
	 * </ul>
	 *
	 * <p>
	 * 기대 결과: 첫 이슈는 cascade=false, 이후 이슈는 cascade=true
	 * </p>
	 * 
	 * @throws IOException
	 */
	@Test
	@DisplayName("첫 번째 오류는 cascade=false(root cause)이고, 이후 발생하는 연쇄 오류는 cascade=true로 표시")
	void verify_MultipleIssues_CascadingFlagged() throws IOException {
		// 1. Given

		// 로그1: 해시 불일치 발생 (Root Cause)
		LogData log1 = new LogData(1, "Log 1", genesisHash, "WRONG_HASH");

		// 로그2: prevHash가 로그1의 currentHash와 다르게 설정하여 연쇄 오류 유도
		// 로그1의 currentHash는 "WRONG_HASH"인데, 로그2는 "ANOTHER_HASH"를 참조하게 함
		LogData log2 = new LogData(2, "Log 2", "ANOTHER_HASH", "HASH_2");

		// 로그 1 모킹 (계산값은 CORRECT_1인데 저장값은 WRONG_HASH인 상태)
		setupMockBehavior(log1, secretKey);
		mockHmacHasher.when(() -> HmacHasher.generateHmac(log1.msg + log1.prevHash, secretKey)).thenReturn("CORRECT_1");

		// 로그 2 모킹
		setupMockBehavior(log2, secretKey);

		Path logFile = createTempLogFile(log1.raw, log2.raw);
		createTempHeadFile(log2.currentHash);

		// 2. When
		LogVerifier verifier = new LogVerifier(mockFormatter);
		LogVerifier.VerifyResult result = verifier.verify(logFile);

		// 3. Then
		assertAll("연쇄 오류 플래그 검증", () -> assertFalse(result.valid),
				() -> assertEquals(2, result.issues.size(), "이슈가 2개 발생해야 함 (Root 1 + Cascade 1)"), () -> {
					LogVerifier.Issue issue1 = result.issues.get(0);
					assertEquals(LogVerifier.IssueType.CURRENT_HASH_MISMATCH, issue1.type);
					assertFalse(issue1.cascade, "첫 번째 이슈는 root cause");
				}, () -> {
					LogVerifier.Issue issue2 = result.issues.get(1);
					assertEquals(LogVerifier.IssueType.PREV_HASH_MISMATCH, issue2.type);
					assertTrue(issue2.cascade, "두 번째 이슈는 chainBroken 이후이므로 cascade=true");
				});
	}

	/**
	 * audit.head 파일과 마지막 로그 해시 불일치 시 TAIL_TRUNCATION 이슈 발생 테스트.
	 *
	 * <p>
	 * 시나리오: audit.head 파일에 저장된 해시와 로그 파일의 마지막 currentHash가 다른 경우
	 * </p>
	 *
	 * <p>
	 * 발생 위치: {@code LogVerifier.verify()} 끝 삭제 탐지 블록 (line 117-119)
	 * </p>
	 * 
	 * <pre>
	 * if (storedHead != null && (lastFileHead == null || !storedHead.equals(lastFileHead))) {
	 * 	issues.add(Issue.tailTruncation(Math.max(1, lineNo), storedHead, lastFileHead));
	 * }
	 * </pre>
	 *
	 * <p>
	 * 추가되는 Issue:
	 * </p>
	 * <ul>
	 * <li>type: {@code TAIL_TRUNCATION}</li>
	 * <li>reason: "파일 끝 로그 삭제/롤백 의심(head 불일치)"</li>
	 * <li>expected: "storedHead={audit.head에 저장된 해시}"</li>
	 * <li>actual: "fileLastHead={로그 파일 마지막 해시}"</li>
	 * <li>cascade: false (독립적인 검사)</li>
	 * </ul>
	 *
	 * <p>
	 * 탐지 가능한 공격:
	 * </p>
	 * <ul>
	 * <li>끝 로그 삭제 (truncation)</li>
	 * <li>로그 파일 롤백 (이전 버전으로 교체)</li>
	 * <li>전체 로그 파일 교체</li>
	 * </ul>
	 *
	 * <p>
	 * 기대 결과: valid=false, issues에 TAIL_TRUNCATION 포함, expected에 storedHead, actual에
	 * fileLastHead
	 * </p>
	 */
	@Test
	@DisplayName("audit.head 파일의 해시와 로그 파일 마지막 currentHash가 다르면 TAIL_TRUNCATION 이슈 발생 (끝 로그 삭제/롤백 탐지)")
	void verify_HeadMismatch_ReturnsTailTruncation() throws IOException {
		// 1. Given

		LogData log1 = new LogData(1, "Log 1", "INIT_SEED_0000", "HASH_1");
		setupMockBehavior(log1, secretKey);

		Path logFile = createTempLogFile(log1.raw);

		// 실제 마지막 로그 해시는 HASH_1인데, head 파일에는 더 미래의 해시인 HASH_2가 적혀있는 상황 (삭제 의심)
		String storedHeadInFile = "FUTURE_HASH_2";
		createTempHeadFile(storedHeadInFile);

		// 2. When
		LogVerifier verifier = new LogVerifier(mockFormatter);
		LogVerifier.VerifyResult result = verifier.verify(logFile);

		// 3. Then
		assertAll("끝 삭제 탐지 검증", () -> assertFalse(result.valid), () -> {
			LogVerifier.Issue issue = result.issues.stream()
					.filter(i -> i.type == LogVerifier.IssueType.TAIL_TRUNCATION).findFirst().orElseThrow();

			assertEquals("storedHead=" + storedHeadInFile, issue.expected);
			assertEquals("fileLastHead=" + log1.currentHash, issue.actual);
			assertFalse(issue.cascade, "Tail Truncation은 독립적인 검사로 cascade=false");
		});
	}

	private void setupMockBehavior(LogData data, String key) {
		String[] parts = data.toParts();
		when(mockFormatter.parse(data.raw)).thenReturn(parts);
		when(mockFormatter.extractMessage(parts)).thenReturn(data.msg);
		when(mockFormatter.extractPrevHash(parts)).thenReturn(data.prevHash);
		when(mockFormatter.extractCurrentHash(parts)).thenReturn(data.currentHash);

		// 해시 계산 결과 모킹
		mockHmacHasher.when(() -> HmacHasher.generateHmac(data.msg + data.prevHash, key)).thenReturn(data.currentHash);
	}

	private Path createTempLogFile(String... lines) throws IOException {
		Path logFile = tempDir.resolve("audit.log");
		Files.writeString(logFile, String.join(System.lineSeparator(), lines));
		return logFile;
	}

	private void createTempHeadFile(String hash) throws IOException {
		Files.writeString(tempDir.resolve("audit.head"), hash);
	}

	// 테스트용 데이터 구조체
	private static class LogData {
		int line;
		String msg;
		String prevHash;
		String currentHash;
		String raw;

		LogData(int line, String msg, String prev, String curr) {
			this.line = line;
			this.msg = msg;
			this.prevHash = prev;
			this.currentHash = curr;
			this.raw = String.format("LINE|%d|%s|%s|%s", line, msg, prev, curr);
		}

		String[] toParts() {
			return raw.split("\\|");
		}
	}
}
