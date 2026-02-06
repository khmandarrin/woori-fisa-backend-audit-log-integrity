package verifier;

import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import util.HmacHasher;
import util.KeyManager;
import util.LogFormatter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 그룹 4: 무결성/체인 깨짐/복합 이슈 테스트
 *
 * <p>예외는 발생하지 않지만 해시 값 비교 결과 불일치가 발생하는 케이스들을 검증한다.</p>
 * <p>로그 변조, 삭제, 순서 변경 등 보안 위협 상황을 탐지하는 로직을 테스트한다.</p>
 *
 * <h2>다루는 Issue 타입</h2>
 * <ul>
 *   <li>{@link verifier.LogVerifier.IssueType#PREV_HASH_MISMATCH}
 *       - 현재 로그의 prevHash가 이전 로그의 currentHash와 불일치 (중간 로그 삭제/순서 변경 의심)</li>
 *   <li>{@link verifier.LogVerifier.IssueType#CURRENT_HASH_MISMATCH}
 *       - currentHash가 HMAC(message + prevHash)와 불일치 (로그 내용 변조 의심)</li>
 *   <li>{@link verifier.LogVerifier.IssueType#TAIL_TRUNCATION}
 *       - audit.head 파일의 해시와 로그 파일 마지막 해시 불일치 (끝 로그 삭제/롤백 의심)</li>
 * </ul>
 *
 * <h2>cascade 플래그</h2>
 * <ul>
 *   <li>cascade=false: 최초 발생 오류 (root cause)</li>
 *   <li>cascade=true: 이전 오류로 인해 파생된 연쇄 오류</li>
 * </ul>
 *
 * <h2>사용하는 Mock 객체</h2>
 * <ul>
 *   <li>{@link LogFormatter} - 로그 파싱 및 필드 추출</li>
 *   <li>{@code MockedStatic<KeyManager>} - 시크릿 키 반환</li>
 *   <li>{@code MockedStatic<HmacHasher>} - HMAC 해시 생성 (불일치 시뮬레이션)</li>
 * </ul>
 */
class LogVerifierIntegrityTest {

    private static Path tempDir;

    @Mock
    private LogFormatter mockFormatter;

    private MockedStatic<KeyManager> mockKeyManager;
    private MockedStatic<HmacHasher> mockHmacHasher;

    private AutoCloseable mocks;

    @BeforeAll
    static void setUpAll() throws IOException {
        tempDir = Files.createTempDirectory("log-verifier-integrity-test");
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
     * previousHash 불일치 시 PREV_HASH_MISMATCH 이슈 발생 테스트.
     *
     * <p>시나리오: 두 번째 로그의 prevHash가 첫 번째 로그의 currentHash와 다른 경우</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 내 체인 검증 블록 (line 85-88)</p>
     * <pre>
     * if (!previousHash.equals(expectedPrevHash)) {
     *     issues.add(Issue.prevHashMismatch(lineNo, expectedPrevHash, previousHash, line, chainBroken));
     *     chainBroken = true;
     * }
     * </pre>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code PREV_HASH_MISMATCH}</li>
     *   <li>reason: "previousHash 체인 불일치"</li>
     *   <li>expected: 이전 로그의 currentHash (또는 GENESIS)</li>
     *   <li>actual: 현재 로그에 기록된 prevHash</li>
     *   <li>rawLine: 체인이 끊긴 로그 라인</li>
     * </ul>
     *
     * <p>탐지 가능한 공격:</p>
     * <ul>
     *   <li>중간 로그 삭제</li>
     *   <li>로그 순서 변경</li>
     *   <li>로그 삽입 (새 로그가 기존 체인과 연결되지 않음)</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 PREV_HASH_MISMATCH 포함, expected/actual 값 검증</p>
     */
    @Test
    @DisplayName("현재 로그의 prevHash가 이전 로그의 currentHash와 다르면 PREV_HASH_MISMATCH 이슈 발생 (중간 로그 삭제/순서 변경 탐지)")
    void verify_PrevHashMismatch_ReturnsPrevHashMismatchError() {
        // TODO
    }

    /**
     * currentHash 불일치 시 CURRENT_HASH_MISMATCH 이슈 발생 테스트.
     *
     * <p>시나리오: 로그에 기록된 currentHash가 HMAC(message + prevHash) 계산 결과와 다른 경우</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 내 해시 무결성 검증 블록 (line 91-97)</p>
     * <pre>
     * String calculatedHash = HmacHasher.generateHmac(message + previousHash, secretKey);
     * if (!currentHash.equals(calculatedHash)) {
     *     issues.add(Issue.currentHashMismatch(lineNo, calculatedHash, currentHash, line, chainBroken));
     *     chainBroken = true;
     * }
     * </pre>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code CURRENT_HASH_MISMATCH}</li>
     *   <li>reason: "currentHash 불일치"</li>
     *   <li>expected: HMAC으로 계산한 올바른 해시값</li>
     *   <li>actual: 로그에 기록된 (변조된) 해시값</li>
     *   <li>rawLine: 변조된 로그 라인</li>
     * </ul>
     *
     * <p>탐지 가능한 공격:</p>
     * <ul>
     *   <li>로그 메시지 내용 변조</li>
     *   <li>해시값 직접 위조</li>
     *   <li>타임스탬프/사용자 정보 변조</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 CURRENT_HASH_MISMATCH 포함, expected에 계산된 해시, actual에 변조된 해시</p>
     */
    @Test
    @DisplayName("로그의 currentHash가 HMAC(message+prevHash) 계산 결과와 다르면 CURRENT_HASH_MISMATCH 이슈 발생 (로그 변조 탐지)")
    void verify_CurrentHashMismatch_ReturnsCurrentHashMismatchError() {
        // TODO
    }

    /**
     * 연쇄 오류(cascading) 발생 시 cascade 플래그 테스트.
     *
     * <p>시나리오: 첫 번째 로그에서 오류 발생 후, 이후 로그들에서 연쇄적으로 오류 발생</p>
     *
     * <p>cascade 플래그 동작:</p>
     * <ul>
     *   <li>첫 번째 오류: chainBroken=false 상태에서 발생 → cascade=false (root cause)</li>
     *   <li>이후 오류: chainBroken=true 상태에서 발생 → cascade=true (연쇄 오류)</li>
     * </ul>
     *
     * <p>예시 흐름:</p>
     * <pre>
     * 로그1: currentHash 변조됨 → CURRENT_HASH_MISMATCH (cascade=false)
     *        chainBroken = true 설정
     * 로그2: prevHash != 로그1의 currentHash → PREV_HASH_MISMATCH (cascade=true)
     * 로그3: 정상이지만 체인이 이미 끊김 → PREV_HASH_MISMATCH (cascade=true)
     * </pre>
     *
     * <p>cascade 플래그의 의미:</p>
     * <ul>
     *   <li>cascade=false: 실제 문제 원인이 되는 로그 (조사 우선순위 높음)</li>
     *   <li>cascade=true: 이전 오류의 영향으로 발생한 오류 (원인 해결 시 자동 해결)</li>
     * </ul>
     *
     * <p>기대 결과: 첫 이슈는 cascade=false, 이후 이슈는 cascade=true</p>
     */
    @Test
    @DisplayName("첫 번째 오류는 cascade=false(root cause)이고, 이후 발생하는 연쇄 오류는 cascade=true로 표시")
    void verify_MultipleIssues_CascadingFlagged() {
        // TODO
    }

    /**
     * audit.head 파일과 마지막 로그 해시 불일치 시 TAIL_TRUNCATION 이슈 발생 테스트.
     *
     * <p>시나리오: audit.head 파일에 저장된 해시와 로그 파일의 마지막 currentHash가 다른 경우</p>
     *
     * <p>발생 위치: {@code LogVerifier.verify()} 끝 삭제 탐지 블록 (line 117-119)</p>
     * <pre>
     * if (storedHead != null && (lastFileHead == null || !storedHead.equals(lastFileHead))) {
     *     issues.add(Issue.tailTruncation(Math.max(1, lineNo), storedHead, lastFileHead));
     * }
     * </pre>
     *
     * <p>추가되는 Issue:</p>
     * <ul>
     *   <li>type: {@code TAIL_TRUNCATION}</li>
     *   <li>reason: "파일 끝 로그 삭제/롤백 의심(head 불일치)"</li>
     *   <li>expected: "storedHead={audit.head에 저장된 해시}"</li>
     *   <li>actual: "fileLastHead={로그 파일 마지막 해시}"</li>
     *   <li>cascade: false (독립적인 검사)</li>
     * </ul>
     *
     * <p>탐지 가능한 공격:</p>
     * <ul>
     *   <li>끝 로그 삭제 (truncation)</li>
     *   <li>로그 파일 롤백 (이전 버전으로 교체)</li>
     *   <li>전체 로그 파일 교체</li>
     * </ul>
     *
     * <p>기대 결과: valid=false, issues에 TAIL_TRUNCATION 포함, expected에 storedHead, actual에 fileLastHead</p>
     */
    @Test
    @DisplayName("audit.head 파일의 해시와 로그 파일 마지막 currentHash가 다르면 TAIL_TRUNCATION 이슈 발생 (끝 로그 삭제/롤백 탐지)")
    void verify_HeadMismatch_ReturnsTailTruncation() {
        // TODO
    }
}
