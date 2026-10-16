Ran command: `ls -la llvm-project/v2/*.md linux/patch/*.md ksmbd/ksmbdzzer.py ksmbd/README.md`
Ran command: `head -n 20 /home/ysk/.gemini/antigravity-ide/brain/ee9c0a1a-493e-4fb0-bb84-4cb560536760/.system_generated/logs/transcript.jsonl 2>/dev/null || true`
Viewed README.md:1-400
Viewed README.md:401-479
Viewed 0001-kcov-add-per-task-dataflow-tracking-for-function-arg.md:1-100
Viewed 0002-Documentation-add-kcov-dataflow.rst.md:1-100
Viewed 0002-Documentation-add-kcov-dataflow.rst.md:101-250
Viewed 0001-SanitizerCoverage-Add-trace-args-and-trace-ret-instr.md:1-80
Viewed 0002-Clang-SanitizerCoverage-Add-fsanitize-coverage-trace.md:1-60
Viewed 0003-compiler-rt-SanitizerCoverage-Add-a-runtime-for-trac.md:1-60
Viewed 0004-compiler-rt-SanitizerCoverage-Add-LibFuzzer-support-.md:1-60
Viewed 0005-Clang-SanitizerCoverage-Document-trace-args-and-trac.md:1-70
Searched for "^def "
Viewed ksmbdzzer.py:1-165
Viewed ksmbdzzer.py:675-840
Searched for "class DataflowRec"
Viewed ksmbdzzer.py:550-615
Viewed ksmbdzzer.py:1870-2000
Viewed ksmbdzzer.py:2001-2150
Viewed ksmbdzzer.py:2151-2185
Viewed common.h:1-120
Viewed common.h:200-350
Viewed gen.py:1-100

[ksmbdzzer.py](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py)는 리눅스 커널의 인-트리(in-tree) SMB 서버인 **ksmbd**를 대상으로 하는 **SMB 프로시저 레벨의 커버리지 가이드 퍼저(Coverage-guided fuzzer)**입니다.

이 프로젝트는 [LLVM 패치](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/)와 [리눅스 커널 패치](file:///home/debian-sid/kcov-dataflow/linux/patch/)를 통해 구현된 **kcov-dataflow**(함수 인자/반환값 및 비교 연산자 추적) 기술을 기반으로 작동하며, 일반적인 크래시뿐만 아니라 **비-크래시 로직 버그 및 쓰기 권한 상승(LPE)**을 전문적으로 탐지하도록 설계되었습니다.

---

### 1. 배경 기술: LLVM 컴파일러 및 커널 패치와의 연계

일반적인 퍼저(예: Syzkaller, AFL)는 "어떤 코드 분기(Edge/PC)를 실행했는가"만 추적합니다. 반면, 본 저장소의 패치들은 함수 경계에서 **"어떤 값(인자 및 반환값)이 오갔는가"**를 추적하는 데이터플로우 신호를 제공합니다.

#### (1) LLVM/Clang 패치 (`llvm-project/v2/*.md`)
- [0001-SanitizerCoverage-Add-trace-args-and-trace-ret-instr.md](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/0001-SanitizerCoverage-Add-trace-args-and-trace-ret-instr.md) & [0002-Clang-SanitizerCoverage-Add-fsanitize-coverage-trace.md](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/0002-Clang-SanitizerCoverage-Add-fsanitize-coverage-trace.md):
  - 컴파일러가 함수 진입 시점에 `__sanitizer_cov_trace_args`, 반환 직전에 `__sanitizer_cov_trace_ret` 콜백을 삽입하도록 `-fsanitize-coverage=trace-args,trace-ret` 플래그를 추가합니다.
  - 구조체 포인터의 경우 DWARF 디버그 정보로부터 필드 오프셋 테이블을 생성하여, 단순 주소가 아닌 내부 필드 값들을 안전하게 분해하여 전달합니다.
- [0003-compiler-rt-SanitizerCoverage-Add-a-runtime-for-trac.md](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/0003-compiler-rt-SanitizerCoverage-Add-a-runtime-for-trac.md) & [0004-compiler-rt-SanitizerCoverage-Add-LibFuzzer-support-.md](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/0004-compiler-rt-SanitizerCoverage-Add-LibFuzzer-support-.md):
  - 유저스페이스 런타임 및 LibFuzzer의 `TracePC::HandleDataflow`를 구현하여 인자/반환값 피처를 값 프로파일 맵에 매핑합니다.
- [0005-Clang-SanitizerCoverage-Document-trace-args-and-trac.md](file:///home/debian-sid/kcov-dataflow/llvm-project/v2/0005-Clang-SanitizerCoverage-Document-trace-args-and-trac.md):
  - 해당 모드의 동작 방식, 콜백 시그니처 및 메모리 안전성(스택 스필 방지 등)을 문서화합니다.

#### (2) 리눅스 커널 패치 (`linux/patch/*.md`)
- [0001-kcov-add-per-task-dataflow-tracking-for-function-arg.md](file:///home/debian-sid/kcov-dataflow/linux/patch/0001-kcov-add-per-task-dataflow-tracking-for-function-arg.md) & [0002-Documentation-add-kcov-dataflow.rst.md](file:///home/debian-sid/kcov-dataflow/linux/patch/0002-Documentation-add-kcov-dataflow.rst.md):
  - 커널 디버그fs에 `/sys/kernel/debug/kcov_dataflow` 디바이스를 신설하고 태스크별 링 버퍼를 제공합니다.
  - 커널 함수 호출 시 전달된 인자(`KCOV_DF_TYPE_ENTRY`), 반환값(`KCOV_DF_TYPE_RET`), 그리고 `trace_cmp` 비교 피연산자 쌍(`KCOV_DF_TYPE_CMP`)을 링 버퍼에 기록합니다.
  - `KCOV_DF_REMOTE_ENABLE` ioctl을 통해 퍼저 프로세스가 커널 워커 스레드(ksmbd 커넥션 핸들러 등)의 원격 커버리지를 자신의 mmap 버퍼로 직접 수집할 수 있습니다.

---

### 2. ksmbdzzer의 핵심 설계 철학 ([README.md](file:///home/debian-sid/kcov-dataflow/ksmbd/README.md))

1. **SMB 프로시저 레벨 퍼징**:
   - syscall 레벨(Syzkaller 방식)이 아닌, **SMB 프로시저(CREATE, WRITE, SET_INFO, IOCTL 등)** 단위로 퍼징을 수행합니다.
2. **Grain (Deep-by-construction) 개념**:
   - SMB 프로토콜은 패킷 구조가 복잡하여 무작위 바이트로 시작하면 초기 파서 단계에서 즉시 드롭됩니다.
   - Grain은 **협상(Negotiate) → NTLMv2 인증 → Tree-Connect → CREATE**까지의 정상적이고 유효한 접두사(Prefix)를 고정해 두고, **마지막 타깃 PDU만 퍼징**합니다.
   - 총 **210개의 Grain**이 정의되어 전체 SMB1/2/3 프로시저, FSCTL, Info-class, RDMA(SMBDirect) 표면을 망라합니다.
3. **Python은 오케스트레이터 역할만 수행 (Orchestrator ONLY)**:
   - Python([ksmbdzzer.py](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py))은 입력 단위의 고속 연산을 직접 하지 않고 스케줄링, 빌드 캐시, 오라클 검증, 코퍼스 영속화만 담당합니다.
   - 초당 수천 회의 실제 뮤테이션, 네트워크 패킷 주입, 커버리지 폴딩은 C 기반 LibFuzzer 하네스([grain/common.h](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h), `libksmbdzzer.so`)가 수행합니다.

---

### 3. [ksmbdzzer.py](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py) 내부 아키텍처 및 4단계 라운드 루프 (`gfuzz`)

[cmd_grain_fuzz()](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L1876-L2176) 함수를 중심으로 4단계 세대 기반 루프가 실행됩니다.

```
ksmbdzzer.py (Orchestrator)
    │
    ├── P1: Enumerate Grains ─── grain/gen.py로 210개 Grain C 하네스 빌드 (컴파일 캐시 적용)
    ├── P2: Saturate Each    ─── CPU 코어별 병렬 워커(Map-Reduce), 루프백 IP 분할 바인딩
    ├── P3: Combine Grains   ─── 공유 객체/핸들에 대한 All-Pairs 조합 (pfz_grain_combo2)
    └── P4: Save & Feed-Fwd  ─── 코퍼스 및 값 풀(Value pool)을 .fuzzdb에 영속화 → 다음 라운드 전달
```

#### P1: Enumerate Grains (하네스 생성 및 컴파일)
- C 라이브러리 `libksmbdzzer.so`에서 등록된 Grain 목록([_get_lib](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L678-L740))을 조회합니다.
- [grain/gen.py](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py)를 통해 각 Grain별 LibFuzzer C 하네스를 자동 생성합니다.
- 소스 코드 해시 기반의 **컴파일 캐시**를 지원하여, 변경이 없을 경우 Clang 재컴파일을 건너뛰고 바로 실행합니다.

#### P2: Saturate Each (개별 Grain 포화 퍼징)
- 가용한 모든 CPU를 활용하여 병렬로 LibFuzzer 하네스를 구동합니다.
- **워커별 루프백 IP 격리 (`127.0.0.<slot>`)**: ksmbd는 클라이언트 IP 기반으로 kcov 원격 핸들을 할당하므로, 각 워커가 고유 루프백 IP를 사용해 커널 커버리지 버퍼 충돌을 원천 방지합니다.
- **Fast-Bail & Session-Drain**: SMB 세션이 맺어지지 않아 커널에 도달하지 못하고 유저스페이스에서 헛도는 프로세스는 즉시 종료(Fast-Bail)하여 불필요한 CPU 소모를 막습니다.

#### P3: Combine Grains (페어 조합 퍼징)
- 2개 이상의 Grain을 단일 세션의 동일 파일 핸들에 순차적/동시적으로 실행합니다 (`pfz_grain_combo2`).
- 예: Grain A가 오플락/리스를 획득한 상태에서 Grain B가 파일 잠금/쓰기를 시도하는 등, 상호작용으로 인해 발생하는 레이스 컨디션 및 상태 오염 버그를 집중 공략합니다.

#### P4: Save & Feed-forward (영속화 및 세대 계승)
- [corpus_save()](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L246-L266)를 통해 획득한 코퍼스와 값 풀(Value pool)을 호스트 마운트 디렉터리(`.fuzzdb/corpus.json`)에 저장합니다.
- 다음 라운드(Generation) 시작 시 이전 라운드의 코퍼스를 기본 탑재하여 시작부터 깊은 커버리지(`ft0`)에서 탐색을 시작합니다.

---

### 4. 하이브리드 뮤테이터 및 데이터플로우 연동 ([grain/common.h](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h))

하네스 내부에서는 커널 데이터플로우 버퍼(`df_buf`)를 실시간으로 참조합니다:

```c
LLVMFuzzerTestOneInput(data):
    타깃 PDU 전송 (Deep-by-construction)
    커널 kcov-dataflow 버퍼 파싱 → ctr[] (__libfuzzer_extra_counters)에 반영
    trace_cmp 피연산자 수집 → 지속 링 버퍼에 저장
    새로운 경로 미발견 시: g_stuck 증가

LLVMFuzzerCustomMutator(data):
    Pass 0 (RedQueen i2s): trace_cmp 비교 피연산자 쌍(a1, a2)을 찾아 입력의 a1을 a2로 치환
    Pass 1 (역방향 토큰 스플라이싱): 커널이 반환했던 파일 핸들/크기/NTSTATUS 등을 입력에 삽입
    정체(Saturation) 시점: 관찰된 인자 값을 데이터 타입 경계값(0, 1, 0x7fff, 0x8000 등)으로 유도
```

- **LibFuzzer에 커널 커버리지 주입**: LibFuzzer는 기본적으로 유저스페이스 엣지만 인식하지만, C 하네스가 커널의 KCOV 및 인자/반환값 정보를 `__libfuzzer_extra_counters`에 복사함으로써 **LibFuzzer의 뮤테이션 엔진이 커널 커버리지에 의해 직접 유도**됩니다.
- **엔진 어블레이션 (`KSMBDZZER_ENGINE`)**: `dataflow-vec`(값 클래스 정규화), `pc-i2s`(경로 전용 + I2S), `pc-havoc`(단순 havoc) 등으로 엔진 모드를 분리하여 데이터플로우 기반 유도 효과를 정량 비교할 수 있습니다.

---

### 5. 3가지 버그 판정 오라클 (Oracle)

단순 커널 패닉만 감시하는 기존 퍼저와 달리, [ksmbdzzer.py](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py)는 세 가지 오라클을 병행 운용합니다.

| 오라클 종류 | 감지 대상 및 원리 | 비고 |
|---|---|---|
| **Crash Oracle** | KASAN (UAF, OOB), UBSAN, Lockdep (데드락), 커널 Panic/Oops | 표준 크래시 감지 |
| **Stability Oracle** | 라운드마다 베이스라인 정상 Grain을 재실행하여 커버리지(`ft0`) 급감 여부 확인 | **비-크래시 버그**: 이전 퍼징으로 인해 ksmbd 내부 전역 상태가 파괴되었음을 감지 |
| **Contract Oracle**<br>([run_dataflow_director](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L1657-L1688)) | root 소유의 테스트 파일에 대해 쓰기/삭제 권한 없이 핸들을 열었음에도 ksmbd가 쓰기/삭제/잠금을 허용하는지 데이터플로우 반환값으로 검증 | **비-크래시 권한 상승(LPE)**: Syzkaller 등 기존 도구로는 탐지 불가능한 접근 제어 우회 탐지 |

---

### 6. 주요 CLI 명령어 및 실행 흐름

- `python3 ksmbdzzer.py init`:
  - [cmd_init](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L268-L446) 실행. 공유 디렉터리 설정, ksmbd 로드, `fuzz:fuzz` 테스트 계정 프로비저닝, Soft-RDMA (SIW/RXE) 구성, `ksmbd.mountd` 구동을 멱등하게 수행합니다.
- `python3 ksmbdzzer.py gfuzz -r 30 --grain-max 40`:
  - [cmd_grain_fuzz](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L1876-L2176) 실행. 30라운드 동안 전체 210개 Grain을 대상으로 포화 퍼징 및 상호작용 조합 퍼징을 전개합니다.
- `python3 ksmbdzzer.py selftest`:
  - [cmd_selftest](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L1725-L1874) 실행. 전체 Grain 중 실제 커널 ksmbd 코드에 정상 도달하는 유효 하위 집합(`WORKING_SUBSET.txt`)을 검증합니다.
- `python3 ksmbdzzer.py build-grains`:
  - [cmd_build_grains](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L2320-L2369) 실행. 게스트 내부의 느린 9p 파일시스템 컴파일 지연을 피하기 위해 호스트 머신에서 전체 Grain 바이너리를 사전 빌드합니다.
- `python3 ksmbdzzer.py probe-test`:
  - [cmd_probe_test](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L2371-L2415) 실행. 쓰기 권한 상승(LPE) 계약 오라클 프로브만 단독 테스트합니다.

---

### 7. 실제 발견 및 패치된 커널 취약점 사례

이 아키텍처를 통해 실제 ksmbd 및 서브시스템에서 다음과 같은 심각한 결함들이 발견되어 패치되었습니다:
1. **`ipc_validate_msg` Slab-OOB Read**: IPC 응답 구조체 검증 전 길이 필드 참조 버그
2. **`ksmbd_alloc_user` Slab-OOB Read**: 버퍼 해시 크기 미검증 결함
3. **`__close_file_table_ids` Cross-Session File Pointer UAF**: 타 세션의 `fp`를 잘못된 테이블에 닫아 발생한 Use-After-Free
4. **SMBDirect `ib_cq_poll_work` Slab-UAF**: RDMA 완성 큐 해제 시 취소 미동기화로 인한 UAF
5. **Oplock Level-II Break 데드락**: 락 역전으로 인한 서버 멈춤 결함

Searched for "TODO"
Viewed gen.py:1730-1760
Viewed ksmbdzzer.py:880-920

현재 **ksmbdzzer**는 이미 일반적인 커널 퍼저(Syzkaller 등) 대비 매우 독창적이고 앞서 있는 아키텍처를 갖추고 있습니다. 

* **Deep-by-construction Grain**: 210개 정상 시나리오의 유효 접두사(Prefix)를 통해 파서 장벽을 돌파
* **kcov-dataflow & trace_cmp**: 커널 함수 인자/반환값 및 비교 연산자를 활용한 RedQueen 스타일 I2S 유도
* **비-크래시 오라클**: 쓰기 권한 상승(LPE) 및 서버 안정성(Stability) Canaries 검증

그러나 코드베이스(예: [grain/gen.py의 TODO](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py#L1733-L1749), [ksmbdzzer.py의 TODO](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L887-L889))와 네트워크 파일 시스템/커널 서버의 특성을 분석해 보면, **뮤테이션 엔진, 프로토콜 상태 모델링, 동시성, 오라클, 실행 성능**의 5가지 핵심 축에서 훨씬 더 강력하게 발전시킬 수 있습니다.

---

### 1. 뮤테이터 및 데이터플로우(I2S) 엔진 고도화

#### (1) Raw PDU Grain 전체에 `GRAIN_I2S_MUTATOR` 롤아웃 (코드 내 미완료 과제)
- **현재 한계**: [grain/gen.py#L1737-L1743](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py#L1737-L1743)에 명시되어 있듯이, v2 하이브리드 Grain에는 I2S 뮤테이터가 적용되었으나 13개의 Raw PDU Grain은 여전히 단순 무작위 Havoc에 의존하고 있습니다.
- **발전 방안**:
  - 13개 Raw Grain 각각에 `g_stuck` 정체 감지 카운터와 `run_target()` 함수를 구현하고 [grain/common.h](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h#L320)의 `GRAIN_I2S_MUTATOR()`를 결합합니다.
  - 동시에 플릿(fleet) 중 일부를 의도적으로 순수 Havoc 대조군(Control group)으로 남겨두어, 데이터플로우 유도 효율을 지속적으로 A/B 벤치마킹하도록 자동화합니다.

#### (2) 인코딩/변환 인식 I2S (Transform-Aware I2S)
- **현재 한계**: 현재 RedQueen I2S는 패킷의 원시 바이트와 커널의 `trace_cmp`/`trace_args` 값이 정확히 1:1로 일치할 때만 치환이 가능합니다. 하지만 SMB 프로토콜은 문자열을 **UTF-16LE**로 인코딩하거나, 파일 오프셋/길이를 **Little-Endian 64비트 정수**로 다루며, SPNEGO/NTLM 등은 **ASN.1 / 해시 / Base64**로 감싸져 있습니다.
- **발전 방안**:
  - `mutate_i2s`에 인코딩 역산 레이어를 추가합니다.
  - 예: 커널이 유니코드 파일명 비교(`smb2_open` 내의 문자열 비교)에서 특정 단어를 요구할 경우, 수집된 ASCII 문자열을 UTF-16LE 바이트 스트림으로 자동 변환하여 페이로드에 스플라이싱합니다.

#### (3) 비교문 거리(Branch Distance) 기반의 값 프로파일링 (AFL++ CMPLOG 스타일)
- **현재 한계**: 비교 연산이 실패할 때 일치/불일치 여부만 보거나 단순 비트맵으로 접습니다.
- **발전 방안**:
  - `trace_cmp`에서 `abs(arg1 - arg2)`의 해밍 거리 및 산술 거리를 계산하여, 거리가 좁혀질 때마다 새로운 커버리지 피처(`ctr[]`)로 보상합니다. 매직 넘버나 크기 경계값을 단계별로 맞춰가는 **그라디언트 유도 퍼징**이 가능해집니다.

---

### 2. 프로토콜 상태 머신 및 시퀀스 체이닝 (Stateful Fuzzing)

#### (1) N-단계 동적 프로시저 체이닝 (Beyond Pairwise Combination)
- **현재 한계**: 현재 P3 단계([cmd_grain_fuzz#L2095](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L2095))는 단 2개의 Grain을 짝지어 실행하는 `C(n+1, 2)` 페어 조합입니다. 그러나 실제 파일 시스템 버그는 3단계 이상의 상호작용(예: `Negotiate -> Auth -> CREATE(Oplock) -> LOCK -> RENAME -> WRITE`)에서 발생하는 복잡한 상태 오염이 많습니다.
- **발전 방안**:
  - 마르코프 체인(Markov Chain) 또는 커버리지 피드백 기반 시퀀스 생성기를 도입합니다.
  - 라운드 P2/P3에서 새로운 커널 PC를 개척한 Grain 시퀀스를 이어붙여 길이 3~5의 **동적 트랜잭션 체인**을 합성합니다.

#### (2) SMB2 Compound Requests (복합 요청) 전문 생성기
- **현재 한계**: 현재 `pfz_compound`가 존재하지만 일부 시나리오에 한정되어 있습니다.
- **발전 방안**:
  - SMB2의 가장 치명적인 취약점 영역 중 하나는 단일 TCP 프레임 안에 여러 명령어를 `NextCommand` 오프셋으로 연결하는 **Compound Request (Compounded Chain)**입니다.
  - 서로 다른 Grain들의 타깃 PDU를 임의로 결합하고, `Related / Unrelated` 플래그 및 파일 ID(`SMB2_NO_FID`)를 엮어주는 자동 복합 PDU 합성기를 구축하면 파서 경계선 버그(`ksmbd_smb2_check_message`, `smb2_calc_size`)를 집중 타격할 수 있습니다.

---

### 3. kcov-dataflow 기반 지능형 레이스 컨디션 유도 (Concurrency Fuzzing)

- **현재 한계**: 현재의 레이스 테스트(`pfz_pool_*_race`)는 스레드 풀에서 단순히 시간차를 두고 동시에 패킷을 쏘는 블랙박스 방식입니다. 커널 내부의 임계 구역(Critical Section)이 매우 짧으면 타이밍이 빗나가기 쉽습니다.
- **발전 방안 (Razzer / KRACE 기법 접목)**:
  - **데이터플로우 트리거 인터셉션**:
    1. Worker A가 특정 파일에 대해 `smb2_lock()` 또는 `smb2_lease_break()`에 진입하여 `kcov_dataflow`에 해당 PC와 인자가 기록되는 순간을 유저스페이스에서 감지합니다.
    2. 그 즉시 Worker B에게 동일한 파일 ID(`fid`)로 `vfs_unlink()`나 `vfs_write()`를 전송하도록 동기화 펄스를 인가합니다.
  - 이를 통해 이전에 발견되었던 `__close_file_table_ids` UAF나 데드락 같은 동시성 결함을 우연이 아닌 **결정론적(Deterministic)**으로 재현할 수 있습니다.

---

### 4. 비-크래시 오라클의 다변화 (Oracle Expansion)

현재의 [run_dataflow_director](file:///home/debian-sid/kcov-dataflow/ksmbd/ksmbdzzer.py#L1657-L1688)에 구현된 쓰기 권한 상승(Write-side LPE) 오라클 외에, 다른 형태의 보안 결함을 잡는 오라클을 추가할 수 있습니다:

| 신규 오라클 | 탐지 기법 및 원리 | 대상 취약점 |
|---|---|---|
| **정보 누출 (Info Leak) 오라클** | 응답 패킷의 패딩 영역 및 구조체 반환 버퍼에 커널 포인터 패턴(`0xffff...`)이나 미초기화 슬랩의 매직 바이트가 유출되는지 검사 | KASLR 우회, 미초기화 커널 스택/힙 누출 (CWE-200) |
| **세션/자격증명 도용 (IDOR) 오라클** | 세션 A(일반 사용자)로 연결된 상태에서 세션 B의 `SessionId`나 `TreeId`, `FileId`를 임의로 지정해 요청을 보냈을 때 `STATUS_USER_SESSION_DELETED` 또는 `STATUS_ACCESS_DENIED`가 아닌 정상 처리되는지 감지 | 권한 우회, 세션 하이재킹 (CWE-284) |
| **자원 누수 (Resource Exhaustion) 오라클** | 매 라운드 종료 시 `/proc/slabinfo`를 조회하여 `ksmbd_fp`, `ksmbd_work`, `ksmbd_session` 등의 캐시 오브젝트 수가 정상적으로 해제(회수)되는지 추적 | 원격 DoS를 유발하는 커널 메모리 누수 |
| **RDMA / SMBDirect 불변식 오라클** | SIW/RXE 가상 RDMA 디바이스의 메모리 영역(MR) 등록/해제 카운터 및 페이지 고정(page pin) 카운터 불일치 감지 | RDMA 서브시스템 메모리 커럽션 |

---

### 5. 아키텍처 및 퍼징 성능 최적화 (Infrastructure)

#### (1) 선언적 Grain 스펙 ($GRAIN_SPEC) 인터프리터화
- **현재 한계**: [grain/gen.py#L1744-L1747](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py#L1744-L1747)에 명시되었듯, 210개의 Grain마다 개별 C 파일을 생성하고 Clang으로 컴파일하는 것은 캐시를 써도 유지보수 비용과 게스트 9p I/O 부하가 큽니다.
- **발전 방안**:
  - 단일 요청형 Grain(write, truncate, setxattr, query_dir 등)은 C 코드를 새로 짜지 않고, 바이트 오프셋과 고정 필드를 정의한 **선언적 스펙(DSL 또는 JSON/바이트코드)** 파일로 분리합니다.
  - 하나의 표준 범용 C 하네스가 런타임에 이 스펙을 읽어 처리하도록 통합하면 **컴파일 오버헤드를 0으로 줄이고 신규 Grain 추가가 즉시 가능**해집니다.

#### (2) VM 메모리 스냅샷 퍼징 (Snapshot Fuzzing) 도입
- **현재 한계**: 아무리 게스트 내부 루프백(`127.0.0.X`)을 써도, TCP 핸드셰이크 + NTLM 인증 과정을 거치는 네트워크 I/O 오버헤드로 인해 초당 수백 회(exec/s) 이상 올리기 어렵습니다.
- **발전 방안**:
  - QEMU/KVM CoW 메모리 스냅샷(AFLplusplus-qemu 또는 Nyx / Agamotto 스타일)을 적용합니다.
  - **`Negotiate -> NTLM 인증 -> Tree-Connect -> CREATE`가 완료되어 TCP 소켓에 타깃 PDU를 대기 중인 상태에서 VM 스냅샷**을 찍어둡니다.
  - 타깃 PDU 1개만 메모리로 직접 주입하고 실행한 뒤 즉시 스냅샷으로 롤백(CoW reset)합니다.
  - 이를 적용하면 복잡한 SMB 인증 네트워크 오버헤드를 완전히 건너뛰어 **초당 수만 회(10,000+ exec/s)의 초고속 퍼징**이 가능해집니다.

---

### 단계별 개발 로드맵 제안

```
[1단계: 단기] (기존 코드 TODO 완성 및 I2S 극대화)
 ├── 13개 Raw Grain에 GRAIN_I2S_MUTATOR 롤아웃 (gen.py TODO 1b)
 ├── UTF-16LE / Little-Endian 정수 변환 인식 I2S 추가
 └── 정보 누출(Info Leak) 응답 패킷 검사 오라클 추가

[2단계: 중기] (상태 및 시퀀스 심화)
 ├── 단일 요청 Grain의 선언적 $GRAIN_SPEC 인터프리터 전환 (gen.py TODO 2)
 ├── 다중 PDU Compound Request 자동 결합 엔진
 └── kcov-dataflow 함수 진입 감지 기반 결정론적 동시성(Race) 인터셉터

[3단계: 장기] (초고속 스케일업)
 ├── SMB 세션 완료 상태 기준 VM 메모리 스냅샷(CoW) 퍼징 도입
 └── IDOR 및 자원 누수(Slab leak) 자동 탐지 오라클 통합
```

현재 인프라가 워낙 탄탄하게 갖추어져 있으므로, **1단계의 Raw Grain I2S 적용 및 프로토콜 변환 인식 I2S**, 그리고 **정보 누출/IDOR 오라클 추가**부터 착수하는 것이 가장 적은 공수로 큰 버그 발굴 효과를 낼 수 있는 방향입니다.

Searched for "smb2.*hdr|transform_hdr|DirectTCP|NetBIOS|smb2_sync_hdr"
Viewed libksmbdzzer.h:80-140
Viewed common.h:520-585
Searched for "pfz_raw_pdu"
Viewed libksmbdzzer.c:640-720
Viewed libksmbdzzer.c:1170-1230
Searched for "GRAINS[]"
Viewed libksmbdzzer.c:6080-6130
Searched for "int grain_write("
Viewed libksmbdzzer.c:3210-3260
Searched for "int pfz_write("
Viewed libksmbdzzer.c:500-540
Searched for "generate_all_grains"
Viewed gen.py:1680-1730
Viewed gen.py:260-350

질문해 주신 내용은 **ksmbdzzer의 구조적 장단점을 관통하는 매우 핵심적인 지점**입니다.

실제 코드베이스([libksmbdzzer.c](file:///home/debian-sid/kcov-dataflow/ksmbd/libksmbdzzer.c), [grain/common.h](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h), [grain/gen.py](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py))를 검증한 결과, **현재 ksmbdzzer는 2개의 계층(Tier)으로 분리**되어 있으며 각각 헤더와 프레임을 다루는 방식에 뚜렷한 한계가 존재합니다.

---

### 1. 현재 ksmbdzzer의 헤더/프레임 처리 현황 점검

#### (1) Tier 1: `libsmbclient` 기반 Grain (210개 중 대다수)
- **동작 방식**: [libksmbdzzer.c:L508](file:///home/debian-sid/kcov-dataflow/ksmbd/libksmbdzzer.c#L508)의 `pfz_write`, `pfz_truncate`, `pfz_setxattr`처럼 Samba의 `libsmbclient` C API(`smbc_write`, `smbc_lseek` 등)를 호출합니다.
- **헤더/프레임 상태**:
  - 퍼저는 POSIX 스타일의 파라미터(오프셋, 버퍼 포인터, 길이)만 라이브러리에 넘깁니다.
  - **SMB2/SMB3 헤더, Direct TCP 프레임 길이, NTLMv2 서명, 패킷 직렬화는 모두 `libsmbclient`가 표준 규격에 맞게 '정상적으로' 만들어 전송**합니다.
  - **장점**: 세션 셋업, 핸드셰이크, 서명이 100% 유효하므로 커널 깊은 곳(VFS 레이어)까지 안정적으로 도달합니다 (Deep-by-construction).
  - **한계**: **SMB 프로토콜 헤더 변조가 완전히 불가능**합니다. 헤더 플래그, 비정상적 크레딧(Credit), 기형적인 NextCommand 오프셋, 잘못된 StructureSize 등 **프로토콜 파서 자체의 취약점은 전혀 건드릴 수 없습니다.**

#### (2) Tier 2: 소켓 기반 Raw-PDU Grain (13개 및 v2 하이브리드 Grain)
- **동작 방식**: [grain/common.h:L530](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h#L530) 및 [grain/gen.py](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py)처럼 포트 445 소켓에 직접 바이트 스트림을 전송합니다.
- **헤더/프레임 상태**:
  1. **Direct TCP 프레이밍 (포함됨)**:
     - [grain/common.h:L543](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/common.h#L543)의 `xact()` 함수를 보면 4바이트 빅엔디안 스트림 헤더(RFC 1002 NetBIOS over TCP 길이)를 직접 빌드합니다:
       ```c
       uint8_t frame[4];
       frame[0]=fl>>24; frame[1]=(fl>>16)&0xff; frame[2]=(fl>>8)&0xff; frame[3]=fl&0xff;
       send(raw_sock, frame, 4, ...);
       ```
  2. **기본 SMB2 헤더 (포함됨, 64바이트 동기식 헤더)**:
     - [libksmbdzzer.h:L98](file:///home/debian-sid/kcov-dataflow/ksmbd/libksmbdzzer.h#L98)의 `smb2_hdr_build()`에서 64바이트 동기식 헤더(`\xfeSMB`)를 직접 조립합니다:
       ```c
       memcpy(h, "\xfeSMB", 4);
       *(uint16_t *)(h + 4) = 64;   // StructureSize
       *(uint16_t *)(h + 12) = cmd;  // Command
       *(uint64_t *)(h + 24) = mid;  // MessageId
       *(uint32_t *)(h + 36) = tid;  // TreeId
       *(uint64_t *)(h + 40) = sid;  // SessionId
       ```
  3. **SMB3 전용 헤더 (미흡/누락)**:
     - **SMB3 Transform Header (`\xfdSMB`)**: 암호화 세션(AES-128/256 GCM)을 감싸는 52바이트 암호화 프레임 헤더(`OriginalMessageSize`, `Nonce`, `Flags`, `Signature`)를 구조적으로 다루지 못함.
     - **SMB3 압축 헤더 (`\xfcSMB`)**: Compression Transform Chaining 헤더 구조체 모델링 부재.
     - **SMBDirect (RDMA) 프레이밍**: `librdmacm`을 통한 소켓 연결은 지원하나, SMBDirect 헤더(`SMB_DIRECT_RESPONSE`, `DataLength`, `RemainingBytes`) 수준의 변조는 제한적임.
  4. **커널 구조체 연동 부재 (원시 바이트 매직 오프셋)**:
     - 커널 소스(`fs/smb/common/smb2pdu.h`)에 존재하는 정식 C 구조체를 include하지 않고, [grain/gen.py:L285](file:///home/debian-sid/kcov-dataflow/ksmbd/grain/gen.py#L285)처럼 **수동 오프셋 캐스팅**을 쓰고 있습니다:
       ```c
       *(uint16_t*)(b2) = 57;               // StructureSize
       *(uint32_t*)(b2+24) = 0x12019F;       // DesiredAccess
       *(uint16_t*)(b2+44) = 120;            // NameOffset
       ```

---

### 2. Syzkaller와 비교했을 때의 근본적인 차이점

| 비교 항목 | Syzkaller (Syzlang 기반) | ksmbdzzer (현재) |
|---|---|---|
| **구조체 인식** | `struct stat`, `msghdr` 등 필드 타입, 포인터, 플래그 비트마스크를 **완전 선언적으로 인지 (Type-aware)** | Tier 1은 블랙박스, Tier 2는 **원시 바이트(Raw blob)에 매직 오프셋 하드코딩** |
| **오프셋-길이 정합성** | `len[buf]`, `offset[ptr]`처럼 버퍼 크기와 오프셋 필드가 **상호 의존적으로 자동 연동/보정**됨 | 뮤테이터가 길이나 오프셋을 임의로 바꾸면 커널 검증문(`smb2_calc_size`)에서 즉시 탈락 |
| **리소스 수명 주기** | `fd = open()`, `read(fd)`처럼 반환된 핸들(`resource`)을 다음 호출의 입력으로 자동 연결 | C 코드에서 수동으로 `memcpy(persistent_fid, ...)`를 하드코딩하여 전달 |

---

### 3. 어떻게 개선할 수 있을까? (구조체 인식 퍼징 발전 방향)

syzkaller처럼 **구조체와 프로토콜 스펙을 인식하는(Structure-aware / Grammar-aware) 퍼저**로 진화시키기 위한 4가지 핵심 개선안입니다.

#### 개선 1: 커널 공식 C 구조체 헤더 직접 바인딩 (Kernel Struct Import)
현재의 `*(uint16_t*)(body + 2) = 112;` 같은 매직 오프셋 방식을 버리고, 리눅스 커널의 SMB 헤더(`fs/smb/common/smb2pdu.h` 또는 `ksmbd/smb2pdu.h`)를 하네스에 직접 `#include`합니다.

```c
// AS-IS: 오프셋 하드코딩 (취약하고 관리 불가)
uint8_t *body = pdu + 64;
*(uint16_t*)(body + 0) = 49;
*(uint32_t*)(body + 4) = payload_len;

// TO-BE: 커널 실제 구조체 매핑
struct smb2_sync_hdr *hdr = (struct smb2_sync_hdr *)pdu;
struct smb2_write_req *req = (struct smb2_write_req *)(pdu + sizeof(*hdr));
req->StructureSize = cpu_to_le16(49);
req->DataOffset = cpu_to_le16(sizeof(*hdr) + sizeof(*req));
req->Length = cpu_to_le32(payload_len);
req->Id.PersistentFileId = g_persistent_id;
```
- **효과**: 컴파일러 차원의 타입 및 크기 검증이 가능해지고, 구조체 패딩 불일치 문제가 완전히 사라집니다.

#### 개선 2: 오프셋/길이 제약 조건 인식 커스텀 뮤테이터 (Constraint-Aware Fixup)
SMB2/3 커널 파서(`ksmbd_smb2_check_message`, `smb2_get_data_area_len`)의 80% 이상은 **`Header + StructureSize + Offset + Length <= MessageLength`** 검증입니다. 
단순 바이트 Havoc은 이 제약을 통과하지 못해 커널 깊은 곳으로 가지 못합니다.

- **Syzkaller/Protobuf 스타일 Fixup 레이어 도입**:
  1. 뮤테이터는 구조체 내부의 의미 있는 필드(플래그, 파일 속성, Oplock/Lease 레벨, 데이터 내용)만 집중적으로 변조합니다.
  2. 전송 직전에 `Fixup()` 단계에서 가변 길이 버퍼(파일명, 쓰기 데이터)의 실제 위치를 계산하여 `DataOffset`, `NameOffset`을 자동 갱신해 줍니다.
  3. 간헐적으로(예: 5% 확률) 의도적인 경계값(1바이트 OOB, 오버플로우 오프셋 `0xFFFF`)을 주입하여 **경계 검증 버그를 정밀 타격**합니다.

#### 개선 3: SMB3 고급 프레임 및 Transform Header 모델링
현재 누락된 SMB3의 핵심 공격 표면을 구조체화합니다.

1. **SMB3 Transform Header (암호화 프레임)**:
   - 커널의 `struct smb2_transform_hdr` (52바이트, `\xfdSMB`)를 정의하여 세션 암호화 상태에서의 프레이밍 조작 지원.
   - `OriginalMessageSize`와 실제 복호화 후 페이로드 크기의 불일치로 유도되는 힙 오버플로우 집중 탐색.
2. **SMB3 Chained Compression Header (`\xfcSMB`)**:
   - `struct smb2_compression_transform_hdr_chained` 구조체를 적용하여 압축 알고리즘(LZNT1, LZ77, LZ4) 및 압축 청크 오프셋 체인 퍼징.
3. **Direct TCP / NetBIOS 프레임 변조**:
   - 4바이트 길이 필드와 실제 전송 바이트 간의 고의적 불일치(Short packet, Giant framing)를 체계적으로 주입.

#### 개선 4: Syzkaller 스타일의 리소스(Resource) 의존성 그래프 도입
- SMB 프로토콜은 핸들 의존성이 절대적입니다:
  - `SessionId` (SessionSetup에서 획득)
  - `TreeId` (TreeConnect에서 획득)
  - `FileId (Persistent/Volatile)` (Create에서 획득)
  - `LeaseKey` / `LockSequence`
- **개선안**:
  - Grain 하네스가 이 리소스들을 하드코딩된 변수가 아니라 **동적 리소스 풀(Resource Pool)**에 등록하도록 구조화합니다.
  - 퍼저 엔진이 Grain A(Session 1)에서 얻은 `FileId`를 Grain B(Session 2)의 요청에 주입하는 등의 **교차 세션/교차 테넌트 IDOR 변조를 프로그래밍 방식으로 자동화**할 수 있습니다.

---

### 결론 요약

> **현재 상태**: 
> 대다수 Grain은 `libsmbclient`에 의존하여 **SMB 헤더/프레임을 직접 다루지 못하며**, 소수의 Raw Grain만이 기본 Direct TCP(4B) 및 SMB2 헤더(64B)를 **원시 바이트 매직 오프셋** 형태로 하드코딩해 사용 중입니다 (SMB3 암호화/압축 헤더는 미흡).
>
> **개선 방향**:
> 커널의 `fs/smb/common/smb2pdu.h` 구조체를 하네스에 직접 바인딩하고, Syzkaller처럼 **구조체 필드 타입과 `Offset-Length` 제약 조건을 인지하는 구조체-인식(Structure-aware) 뮤테이터**로 전환하면, 파서에서 튕겨 나가는 낭비(Waste exec)를 없애고 훨씬 깊은 프로토콜 로직 버그를 발굴할 수 있습니다.