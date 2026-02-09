package verifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mockStatic;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

/**
 * 그룹 1: 입력/파일 상태 검증 테스트
 *
 * <p>
 * verify() 메서드가 실제 로그 검증 로직에 진입하기 전 처리하는 케이스들을 검증한다.
 * </p>
 * <p>
 * 파일 시스템 상태나 입력값 자체의 유효성을 검증한다.
 * </p>
 *
 * <h2>다루는 Issue 타입</h2>
 * <ul>
 * <li>{@link verifier.LogVerifier.IssueType#SYSTEM_ERROR} - null 경로, 파일 없음 등 시스템 레벨 오류</li>
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
class LogVerifierInputValidationTest {

	private static Path tempDir;
	private static final String SECRET_KEY = "TEST_SECRET";

	@Mock
	private LogFormatter mockFormatter;

	@BeforeAll
	static void setUpAll() throws IOException {
		// 테스트용 임시 디렉토리 생성
		tempDir = Files.createTempDirectory("log-verifier-input-test");
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

	// ==================== null / 파일 존재 여부 ====================

	/**
	 * auditLogPath가 null인 경우 테스트.
	 *
	 * <p>
	 * 시나리오: verify() 메서드에 null 경로가 전달된 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>auditLogPath == null 검사</li>
	 * <li>VerifyResult.fail() 호출로 즉시 실패 반환</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: {@code SYSTEM_ERROR} - "auditLogPath가 null 입니다."
	 * </p>
	 * <p>
	 * 기대 결과: valid=false, processedLines=0, issues=[SYSTEM_ERROR]
	 * </p>
	 */
	@Test
	@DisplayName("null 경로 검증: auditLogPath가 null이면 SYSTEM_ERROR 반환")
	void verify_NullPath_ReturnsFail() throws IOException {
		// given
		Path nullPath = null;
		LogVerifier verifier = new LogVerifier();

		// when
		LogVerifier.VerifyResult result = verifier.verify(nullPath);

		// then
		assertFalse(result.valid);
		assertEquals(0, result.processedLines);
		assertEquals(1, result.issues.size());

		LogVerifier.Issue issue = result.issues.get(0);
		assertEquals(LogVerifier.IssueType.SYSTEM_ERROR, issue.type);
	}

	/**
	 * auditLogPath가 존재하지 않는 파일 경로인 경우 테스트.
	 *
	 * <p>
	 * 시나리오: 실제로 존재하지 않는 파일 경로가 전달된 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>Files.exists(auditLogPath) == false 검사</li>
	 * <li>VerifyResult.fail() 호출로 즉시 실패 반환</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: {@code SYSTEM_ERROR} - "파일이 존재하지 않습니다: {path}"
	 * </p>
	 * <p>
	 * 기대 결과: valid=false, processedLines=0, issues=[SYSTEM_ERROR]
	 * </p>
	 */
	@Test
	@DisplayName("존재하지 않는 파일 검증: 파일이 없으면 SYSTEM_ERROR 반환")
	void verify_NonExistentFile_ReturnsFail() throws IOException {
		// given
		Path nonExistentPath = tempDir.resolve("non-existent-file.log");
		LogVerifier verifier = new LogVerifier();

		// when
		LogVerifier.VerifyResult result = verifier.verify(nonExistentPath);

		// then
		assertFalse(result.valid);
		assertEquals(0, result.processedLines);
		assertEquals(1, result.issues.size());

		LogVerifier.Issue issue = result.issues.get(0);
		assertEquals(LogVerifier.IssueType.SYSTEM_ERROR, issue.type);
	}

	// ==================== 빈 파일 / 공백 라인 ====================

	/**
	 * 빈 파일(내용 없음)인 경우 테스트.
	 *
	 * <p>
	 * 시나리오: 파일은 존재하지만 내용이 비어있는 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>while 루프 진입하지 않음 (읽을 라인 없음)</li>
	 * <li>검증할 로그가 없으므로 정상 처리</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=0, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("빈 파일 검증: 내용이 없으면 valid=true, processedLines=0 반환")
	void verify_EmptyFile_ReturnsSuccess() throws IOException {
		// given
		Path emptyFile = tempDir.resolve("empty.log");
		Files.writeString(emptyFile, "");
		LogVerifier verifier = new LogVerifier();

		// when
		LogVerifier.VerifyResult result = verifier.verify(emptyFile);

		// then
		assertTrue(result.valid);
		assertEquals(0, result.processedLines);
		assertTrue(result.issues.isEmpty());
	}

	/**
	 * 공백 라인만 존재하는 파일인 경우 테스트.
	 *
	 * <p>
	 * 시나리오: 파일에 공백/탭/개행만 있고 실제 로그는 없는 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>while 루프에서 각 라인 읽음</li>
	 * <li>line.trim().isEmpty() == true → continue로 스킵</li>
	 * <li>모든 라인 스킵 후 정상 종료</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=0, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("공백 라인 검증: 공백만 있으면 모두 스킵하고 valid=true 반환")
	void verify_OnlyWhitespaceLines_ReturnsSuccess() throws IOException {
		// given
		Path whitespaceFile = tempDir.resolve("whitespace.log");
		Files.writeString(whitespaceFile, "   \n\n\t\t\n   \n");
		LogVerifier verifier = new LogVerifier();

		// when
		LogVerifier.VerifyResult result = verifier.verify(whitespaceFile);

		// then
		assertTrue(result.valid);
		assertEquals(0, result.processedLines);
		assertTrue(result.issues.isEmpty());
	}

	// ==================== audit.head 파일 상태 ====================

	/**
	 * audit.head 파일이 존재하지 않는 경우 테스트.
	 *
	 * <p>
	 * 시나리오: 로그 파일은 정상이지만 audit.head 파일이 없는 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>로그 체인 검증 정상 통과</li>
	 * <li>Files.exists(headPath) == false → truncation 검사 스킵</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음 (truncation 검사 스킵)
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=1, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("head 파일 없음: audit.head가 없으면 TAIL_TRUNCATION 검사 스킵")
	void verify_NoHeadFile_SkipsTruncationCheck() throws Exception {
		// given
		Path subDir = Files.createTempDirectory(tempDir, "no-head-test");
		Path logFile = subDir.resolve("audit.log");

		String rawLine = "RAW_LOG_LINE";
		Files.writeString(logFile, rawLine);

		// 모킹에 사용할 기대값들
		String message = "테스트 로그";
		String prevHash = "INIT_SEED_0000";
		String currentHash = "HASH1";
		String[] parsed = {"parsed_0"};

		// audit.head 파일은 생성하지 않음

		// Mocking: Formatter 동작 정의
		given(mockFormatter.parse(rawLine)).willReturn(parsed);
		given(mockFormatter.extractMessage(parsed)).willReturn(message);
		given(mockFormatter.extractPrevHash(parsed)).willReturn(prevHash);
		given(mockFormatter.extractCurrentHash(parsed)).willReturn(currentHash);

		try (MockedStatic<KeyManager> keyManagerMock = mockStatic(KeyManager.class);
				MockedStatic<HmacHasher> hmacMock = mockStatic(HmacHasher.class)) {

			// 전역 설정 모킹
			keyManagerMock.when(KeyManager::getSecretKey).thenReturn(SECRET_KEY);
			// 해시 계산 결과 모킹
			hmacMock.when(() -> HmacHasher.generateHmac(message + prevHash, SECRET_KEY)).thenReturn(currentHash);

			LogVerifier verifier = new LogVerifier(mockFormatter);

			// when
			LogVerifier.VerifyResult result = verifier.verify(logFile);

			// then
			assertTrue(result.valid);
			assertEquals(1, result.processedLines);
			assertTrue(result.issues.isEmpty());
		}
	}

	/**
	 * audit.head 파일이 존재하지만 비어있는 경우 테스트.
	 *
	 * <p>
	 * 시나리오: audit.head 파일은 있지만 내용이 비어있는 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>로그 체인 검증 정상 통과</li>
	 * <li>storedHead.isEmpty() == true → storedHead = null 처리</li>
	 * <li>storedHead == null → truncation 검사 스킵</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음 (빈 head 파일은 없는 것과 동일 처리)
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=1, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("빈 head 파일: audit.head가 비어있으면 TAIL_TRUNCATION 검사 스킵")
	void verify_EmptyHeadFile_SkipsTruncationCheck() throws Exception {
		// given
		Path subDir = Files.createTempDirectory(tempDir, "empty-head-test");
		Path logFile = subDir.resolve("audit.log");

		String rawLine = "RAW_LOG_LINE";
		Files.writeString(logFile, rawLine);

		// 빈 head 파일 생성
		Files.writeString(logFile.resolveSibling("audit.head"), "");

		// 모킹에 사용할 기대값들
		String message = "테스트 로그";
		String prevHash = "INIT_SEED_0000";
		String currentHash = "HASH1";
		String[] parsed = {"parsed_0"};

		// Mocking: Formatter 동작 정의
		given(mockFormatter.parse(rawLine)).willReturn(parsed);
		given(mockFormatter.extractMessage(parsed)).willReturn(message);
		given(mockFormatter.extractPrevHash(parsed)).willReturn(prevHash);
		given(mockFormatter.extractCurrentHash(parsed)).willReturn(currentHash);

		try (MockedStatic<KeyManager> keyManagerMock = mockStatic(KeyManager.class);
				MockedStatic<HmacHasher> hmacMock = mockStatic(HmacHasher.class)) {

			// 전역 설정 모킹
			keyManagerMock.when(KeyManager::getSecretKey).thenReturn(SECRET_KEY);
			// 해시 계산 결과 모킹
			hmacMock.when(() -> HmacHasher.generateHmac(message + prevHash, SECRET_KEY)).thenReturn(currentHash);

			LogVerifier verifier = new LogVerifier(mockFormatter);

			// when
			LogVerifier.VerifyResult result = verifier.verify(logFile);

			// then
			assertTrue(result.valid);
			assertEquals(1, result.processedLines);
			assertTrue(result.issues.isEmpty());
		}
	}

	/**
	 * audit.head 파일이 존재하고 마지막 로그 해시와 일치하는 경우 테스트.
	 *
	 * <p>
	 * 시나리오: 로그 체인이 정상이고 audit.head도 마지막 해시와 일치하는 경우
	 * </p>
	 *
	 * <p>
	 * 검증 흐름:
	 * </p>
	 * <ol>
	 * <li>로그 체인 검증 정상 통과</li>
	 * <li>storedHead.equals(lastFileHead) == true → 정상</li>
	 * </ol>
	 *
	 * <p>
	 * 추가되는 Issue: 없음 (일치하므로 정상)
	 * </p>
	 * <p>
	 * 기대 결과: valid=true, processedLines=1, issues=[]
	 * </p>
	 */
	@Test
	@DisplayName("head 파일 일치: audit.head와 마지막 해시가 같으면 valid=true 반환")
	void verify_HeadFileMatches_ReturnsSuccess() throws Exception {
		// given
		Path subDir = Files.createTempDirectory(tempDir, "matching-head-test");
		Path logFile = subDir.resolve("audit.log");

		String rawLine = "RAW_LOG_LINE";
		Files.writeString(logFile, rawLine);

		// 모킹에 사용할 기대값들
		String message = "테스트 로그";
		String prevHash = "INIT_SEED_0000";
		String currentHash = "HASH1";
		String[] parsed = {"parsed_0"};

		// head 파일에 마지막 해시와 일치하는 값 저장
		Files.writeString(logFile.resolveSibling("audit.head"), currentHash);

		// Mocking: Formatter 동작 정의
		given(mockFormatter.parse(rawLine)).willReturn(parsed);
		given(mockFormatter.extractMessage(parsed)).willReturn(message);
		given(mockFormatter.extractPrevHash(parsed)).willReturn(prevHash);
		given(mockFormatter.extractCurrentHash(parsed)).willReturn(currentHash);

		try (MockedStatic<KeyManager> keyManagerMock = mockStatic(KeyManager.class);
				MockedStatic<HmacHasher> hmacMock = mockStatic(HmacHasher.class)) {

			// 전역 설정 모킹
			keyManagerMock.when(KeyManager::getSecretKey).thenReturn(SECRET_KEY);
			// 해시 계산 결과 모킹
			hmacMock.when(() -> HmacHasher.generateHmac(message + prevHash, SECRET_KEY)).thenReturn(currentHash);

			LogVerifier verifier = new LogVerifier(mockFormatter);

			// when
			LogVerifier.VerifyResult result = verifier.verify(logFile);

			// then
			assertTrue(result.valid);
			assertEquals(1, result.processedLines);
			assertTrue(result.issues.isEmpty());
		}
	}
}
