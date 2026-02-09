package verifier;

import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * 그룹 3: 파싱/해시 생성 예외 테스트
 *
 * <p>로그 처리 중 예외(Exception)가 발생하는 케이스들을 검증한다.</p>
 * <p>로그 포맷 오류나 HMAC 계산 실패 등 예외 상황에서의 Issue 생성을 테스트한다.</p>
 *
 * <h2>다루는 Issue 타입</h2>
 * <ul>
 *   <li>{@link verifier.LogVerifier.IssueType#PARSE_ERROR}
 *       - formatter.parse()에서 IllegalArgumentException 발생 시</li>
 *   <li>{@link verifier.LogVerifier.IssueType#HASH_CALC_ERROR}
 *       - HmacHasher.generateHmac()에서 Exception 발생 시</li>
 * </ul>
 *
 * <h2>사용하는 Mock 객체</h2>
 * <ul>
 *   <li>{@link LogFormatter} - parse() 예외 발생 시뮬레이션</li>
 *   <li>{@code MockedStatic<KeyManager>} - 시크릿 키 반환</li>
 *   <li>{@code MockedStatic<HmacHasher>} - generateHmac() 예외 발생 시뮬레이션</li>
 * </ul>
 */
class LogVerifierExceptionTest {

    private static Path tempDir;

    @Mock
    private LogFormatter mockFormatter;

    private AutoCloseable mocks;

    @BeforeAll
    static void setUpAll() throws IOException {
        tempDir = Files.createTempDirectory("log-verifier-exception-test");
    }

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @AfterAll
    static void tearDownAll() throws IOException {
        Files.walk(tempDir)
             .sorted((a, b) -> -a.compareTo(b))
             .forEach(p -> { try { Files.delete(p); } catch (Exception ignored) {} });
    }

    /**
     * 로그 파싱 실패 시 PARSE_ERROR 이슈 발생 테스트.
     *
     * <p>시나리오: formatter.parse() 호출 시 IllegalArgumentException 발생</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 내 try-catch 블록 (line 71-77)</p>
     * <pre>
     * try {
     *     parts = formatter.parse(line);
     * } catch (IllegalArgumentException e) {
     *     issues.add(Issue.parseError(lineNo, e.getMessage(), line, chainBroken));
     *     chainBroken = true;
     *     continue;
     * }
     * </pre>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code PARSE_ERROR}</li>
     *   <li>reason: "로그 파싱 실패: {예외 메시지}"</li>
     *   <li>rawLine: 파싱 실패한 원본 로그 라인</li>
     *   <li>cascade: 첫 번째 오류면 false, 이후 오류면 true</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 PARSE_ERROR 포함</p>
     */
    @Test
    @DisplayName("formatter.parse()에서 IllegalArgumentException 발생 시 PARSE_ERROR 이슈가 추가되고 valid=false 반환")
    void verify_ParseFailure_ReturnsParseError() throws Exception{
    	 // given: 임시 로그 파일 1줄 생성
        Path auditLog = tempDir.resolve("audit.log");
        Files.writeString(auditLog, "INVALID_LOG_LINE\n", StandardCharsets.UTF_8);

        // given: formatter.parse()가 호출되면 무조건 예외를 던지도록 설정 (mockFormatter 사용)
        when(mockFormatter.parse(anyString()))
                .thenThrow(new IllegalArgumentException("bad format"));

        LogVerifier verifier = new LogVerifier(mockFormatter);

        // when
        LogVerifier.VerifyResult result = verifier.verify(auditLog);

        // then: valid=false
        assertFalse(result.valid);

        // then: issues에 PARSE_ERROR 포함
        assertTrue(
                result.issues.stream().anyMatch(i -> i.type == LogVerifier.IssueType.PARSE_ERROR),
                "issues에 PARSE_ERROR가 포함되어야 합니다."
        );
    }
    

    /**
     * HMAC 해시 생성 실패 시 HASH_CALC_ERROR 이슈 발생 테스트.
     *
     * <p>시나리오: HmacHasher.generateHmac() 호출 시 GeneralSecurityException 발생</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 내 try-catch 블록 (line 92-101)</p>
     * <pre>
     * try {
     *     String calculatedHash = HmacHasher.generateHmac(message + previousHash, secretKey);
     *     ...
     * } catch (Exception e) {
     *     issues.add(Issue.hashCalcError(lineNo, e.getMessage(), line, chainBroken));
     *     chainBroken = true;
     * }
     * </pre>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code HASH_CALC_ERROR}</li>
     *   <li>reason: "HMAC 계산 실패: {예외 메시지}"</li>
     *   <li>rawLine: 해시 계산 실패한 원본 로그 라인</li>
     *   <li>cascade: 첫 번째 오류면 false, 이후 오류면 true</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 HASH_CALC_ERROR 포함</p>
     */
    @Test
    @DisplayName("HmacHasher.generateHmac()에서 GeneralSecurityException 발생 시 HASH_CALC_ERROR 이슈가 추가되고 valid=false 반환")
    void verify_HmacGenerationFailure_ReturnsHashCalcError() throws Exception{
    	// given: 임시 로그 파일(1줄)
        Path auditLog = tempDir.resolve("audit-hmac-gensec-error.log");
        Files.writeString(auditLog,
                "2026-02-04 17:27:24 | admin001 | 192.168.1.100 | 관리자 로그인 | curHash=AAA | prevHash=BBB\n",
                StandardCharsets.UTF_8);

        // parse + 추출 메서드 스텁 (null 방지 & prevHash 체인 통과)
        when(mockFormatter.parse(anyString())).thenReturn(new String[] { "dummy" });
        when(mockFormatter.extractMessage(any(String[].class))).thenReturn("messagePart");
        when(mockFormatter.extractCurrentHash(any(String[].class))).thenReturn("AAA");
        when(mockFormatter.extractPrevHash(any(String[].class))).thenReturn("INIT_SEED_0000");

        try (MockedStatic<KeyManager> km = Mockito.mockStatic(KeyManager.class);
             MockedStatic<HmacHasher> hh = Mockito.mockStatic(HmacHasher.class)) {

            km.when(KeyManager::getSecretKey).thenReturn("secret");

            // when: LogVerifier가 실제로 잡는 예외 타입은 GeneralSecurityException 뿐
            // HMAC 계산 시 암호화 관련 checked 예외 발생(= LogVerifier가 catch하는 타입)
            hh.when(() -> HmacHasher.generateHmac(Mockito.anyString(), Mockito.anyString()))
              .thenThrow(new GeneralSecurityException("HMAC Calculation Failed"));

            LogVerifier verifier = new LogVerifier(mockFormatter);
            
            //when
            LogVerifier.VerifyResult result = verifier.verify(auditLog);

            // then
            assertFalse(result.valid);

            assertTrue(
                result.issues.stream().anyMatch(i -> i.type == LogVerifier.IssueType.HASH_CALC_ERROR),
                "issues에 HASH_CALC_ERROR가 포함되어야 합니다."
            );

            assertTrue(
                result.issues.stream()
                    .filter(i -> i.type == LogVerifier.IssueType.HASH_CALC_ERROR)
                    .anyMatch(i -> i.reason.contains("HMAC Calculation Failed")),
                "HASH_CALC_ERROR reason에 원본 예외 메시지가 포함되어야 합니다."
            );
        }
    }

    /**
     * HMAC 계산 중 일반 Exception 발생 시 HASH_CALC_ERROR 이슈 생성 테스트.
     *
     * <p>시나리오: HmacHasher.generateHmac() 호출 시 checked Exception 발생</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 내 try-catch 블록 (line 92-101)</p>
     *
     * <p>Exception 발생 원인 예시:</p>
     * <ul>
     *   <li>잘못된 알고리즘 지정 (NoSuchAlgorithmException)</li>
     *   <li>잘못된 키 형식 (InvalidKeyException)</li>
     *   <li>암호화 관련 오류</li>
     * </ul>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code HASH_CALC_ERROR}</li>
     *   <li>reason: "HMAC 계산 실패: {예외 메시지}"</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 HASH_CALC_ERROR 포함, reason에 "HMAC 계산 실패" 문자열 포함</p>
     */
    @Test
    @DisplayName("HmacHasher.generateHmac()에서 checked Exception 발생 시 HASH_CALC_ERROR 이슈가 추가되고 reason에 'HMAC 계산 실패' 포함")
    void verify_HmacException_CreatesHashCalcErrorIssue() throws Exception{
    	// given: 로그 1줄 준비
        Path auditLog = tempDir.resolve("audit-hmac-checked-exception.log");
        Files.writeString(
            auditLog,
            "2026-02-04 17:27:24 | admin001 | 192.168.1.100 | 관리자 로그인 | curHash=AAA | prevHash=BBB\n",
            StandardCharsets.UTF_8
        );

        // formatter mock: 파싱/추출이 모두 정상 동작하도록 스텁 (null 방지 + 체인검증 통과)
        when(mockFormatter.parse(anyString())).thenReturn(new String[] { "dummy" });
        when(mockFormatter.extractMessage(any(String[].class))).thenReturn("messagePart");
        when(mockFormatter.extractCurrentHash(any(String[].class))).thenReturn("AAA");

        // 첫 줄 expectedPrevHash는 INIT_SEED_0000 이므로 동일하게 맞춰 PREV_HASH_MISMATCH를 막는다.
        when(mockFormatter.extractPrevHash(any(String[].class))).thenReturn("INIT_SEED_0000");

        // static mocking 범위 제한
        try (MockedStatic<KeyManager> km = Mockito.mockStatic(KeyManager.class);
             MockedStatic<HmacHasher> hh = Mockito.mockStatic(HmacHasher.class)) {

            // KeyManager.getSecretKey() 정상 반환
            km.when(KeyManager::getSecretKey).thenReturn("secret");

            // when: HMAC 계산 시 checked Exception(예: NoSuchAlgorithmException) 발생
            hh.when(() -> HmacHasher.generateHmac(Mockito.anyString(), Mockito.anyString()))
              .thenThrow(new NoSuchAlgorithmException("No such algorithm"));

            LogVerifier verifier = new LogVerifier(mockFormatter);
            LogVerifier.VerifyResult result = verifier.verify(auditLog);

            // then: valid=false
            assertFalse(result.valid, "HMAC 계산 예외 발생 시 valid는 false여야 합니다.");

            // then: HASH_CALC_ERROR 포함
            assertTrue(
                result.issues.stream().anyMatch(i -> i.type == LogVerifier.IssueType.HASH_CALC_ERROR),
                "issues에 HASH_CALC_ERROR가 포함되어야 합니다."
            );

            // then: reason에 'HMAC 계산 실패' 포함
            assertTrue(
					result.issues.stream().filter(i -> i.type == LogVerifier.IssueType.HASH_CALC_ERROR)
							.anyMatch(i -> i.reason.contains("HMAC 계산 실패")),
					"HASH_CALC_ERROR reason에 'HMAC 계산 실패' 문자열이 포함되어야 합니다.");

		}
	}
}
