# [American Fuzzy Lop internals](http://shimasyaro.hatenablog.com/entry/2018/03/26/184415)

### American Fuzzy Lop 소스 코드 분석

최근 American Fuzzy Lop에 대한 여러가지 기술을 탑재하는 과정에서 소스 코드 분석을 했으므로, 그 결과를 블로그에 정리해서 올려보자는 생각으로 적어 보았습니다.

소스 코드의 분석을 하는 블로그 등은 딱히 본 적이 없기 때문에 (2018/03/19 시점) 쓸 가치가 있다고 생각하여 자기 만족으로 적어 보았습니다.



### American Fuzzy Lop란

American Fuzzy Lop은 Google의 엔지니어인 Michal Zalewski의 fuzzing tool입니다.

fuzzing은 간단하게 말해서 "자동으로 버그, 취약점을 찾자" 라는 개념입니다.



유명한 사례로서는 CGC(Cyber Grand Challenge) 컴퓨터 간 공방에서 fuzzing이 사용되기도 하며, 

또 최근 사건으로는 2017년 보도된 Microsoft의 [Security Risk Detection](https://www.microsoft.com/en-us/security-risk-detection/) 툴은 [Neural fuzzing: applying DNN to software security testing](https://www.microsoft.com/en-us/security-risk-detection/) 에 작성되어 있듯이 fuzzing의 알고리즘에 Deep Neural Network를 적용하고 있습니다.



즉, "자동으로 버그나 취약점을 찾는 서비스를 시작했다." 라는 말입니다. 유명한 기업이 이런 일을 하고 있을 정도로 뜨거운 화제이므로 흥미가 있으면 꼭 이 글을 시작으로 fuzzing에 뛰어들면 좋겠습니다.



### American Fuzzy Lop의 알고리즘에 대해서

American Fuzzy Lop의 알고리즘은 유전적 알고리즘입니다. 

더 간단하게 말하면 "테스트 하는 실행 속도가 빠르기에 코드 커버리지가 (이하, 커버리지) 넓고 더 깊이까지 테스트 할 수 있는 것이 좋은 케이스" 라는 생각을 기반으로 구현되었습니다.



American Fuzzy Lop로는 "어쨌든 빠르고 정확하며, 많은 불필요한 부분을 (불필요한 라이브러리로 CPU를 많이 사용하는 등) 제외한 심플한 소스 코드이다." 라는 컨셉을 하고 있습니다. 



### American Fuzzy Lop의 변형에 대해서

변형 (Mutation) 이란 유저가 준비한 초기 값을 여러 가지 방식으로 변화하는 방법입니다.

방식은 크게 나눠 6개가 있습니다.

* SIMPLE BITFLIP (xor)
* ARITHMETIC INC/DEC (수의 증가/감소)
* INTERESTING VALUES (고정치 삽입)
* DICTIONARY STUFF (사전형 data 삽입)
* RANDOM HAVOC (랜덤으로 준비된 방법 선택)
* SPLICING (data splite)

이 글에서는 소스 코드를 (afl-fuzz.c의 fuzz_one 함수) 통해 6개의 방식을 자세하고 간단하게 설명하도록 하겠습니다.

아래 링크는 소스 코드에 메모를 적어둔 것이므로 필요하시면 이용하시기 바랍니다. (afl-2.25b 디렉토리에 있습니다.)

[https://github.com/syarochan/public_study](https://github.com/syarochan/public_study)



### 변형에 들어가기 전 처리 (불필요한 data skip)

변형에 (Mutation) 들어가기 전 최소한의 fuzzing을 위하여 불필요한 data를 (queue) 삭제합니다.

삭제되는 data는 이하 3개입니다.

* 에러를 찾기 위해 변형 처리를 기다리는 data가 (pending_favored) 있고, 그 data가 이미 fuzzing 된 data (already-fuzzed, was_fuzzed) 또는 에러를 찾고 있지 않는 data (non-favored, !favored) 일 경우에는 99%의 확률로 변형을 하지 않고 return 합니다.

* 아래 3개의 조건이 갖춰졌을 때 아래 2가지 조건으로 분기합니다.

  1. penging_favored가 없을 경우 fuzzing을 실행할 때 옵션이 dumb_mode가 아닐 것. (유저의 초기 값으로만 fuzzing을 하는 모드)
  2. 현재의 data가 에러를 찾는 data가 (favored queue) 아닐 것.
  3. 변형 처리를 기다리는 queue의 수가 (queue_paths) 10개 보다 적을 것.

  * 아래 2가지 조건이 충족되면 75%의 확률로 변형을 수행하지 않고 return 합니다.
    1. queue_paths에 있는 queue를 한 바퀴 돌고나서 더해지는 수가 (queue cycle) 1보다 위 일 것.
    2. 이미 fuzzing 되고 있는 queue 일 것.
  * 그 이외의 조건이라면 95% 확률로 변형을 수행하지 않고 return 합니다.

아래는 설명한 내용에 대한 소스 코드입니다.

```c
#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
// already-fuzzed와 non-favored는 99%의 확률로 skip 됩니다.
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {// pending_favored가 없을 경우 이 조건을 비교합니다.

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {//lower for never-fuzzed entries.

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;// 75%의 확률로 return

    } else {//higher for already-fuzzed

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;// 95%의 확률로 return

    }

  }

#endif /* ^IGNORE_FINDS */
```



### 변형에 들어가기 전 처리 (CALIBRATION을 실패한 data가 있을 때)

* CALIBRATION이란 실제로 data를 (queue) 사용하여 실행 파일을 실행하고 해당 queue의 커버리지, 실행 속도, 어떤 에러가 발생하는지 등을 기록하는 함수입니다.
* 아래는 calibrate_case 함수의 설명입니다.
* fuzz_one 함수에 들어가기 전 단계에서 calibration 함수는 실행 되어 있으며, 실행 실패 flag는 (cal_failed) calibration 함수가 실행된 직후 설정됩니다.
* 디폴트의 상태이면 (dumb_mode가 아닌 상태) init_forkserver를 사용하여 자식 프로세스를 생성합니다.
* write_to_testcase로 .cur_input 파일에 data 내용을 작성합니다.
* 작성한 후, run_target 함수를 통해 자식 프로세스에서 execv로 실행 파일을 실행하고, 실행 결과를 부모 프로세스에 반환합니다.
* stage는 모두 8번 (fast calibration의 flag가 설정 되어 있지 않을 때) 실행됩니다. 즉, run_target도 8번 실행됩니다.
* run_target이 끝날 때마다 커버리지를 (trace_bits) 사용하여 hash를 생성합니다.
* hash는 최초 run_target을 실행할 때의 hash를 현재 queue에 저장한 후, 최초 커버리지를 first_trace에 넣어 나중의 stage와 비교합니다.
* 두번째 이후 생성된 hash가 처음 hash와 다를 경우, 새로운 input의 편성으로 (new tuple) 새로운 커버리지를 찾았기에 전체의 커버리지를 (virgin_bits) 갱신합니다.
* first trace와 trace bits를 비교해나가며 일치하지 않은 부분이 있다면 해당 부분에 (var_bytes) flag를 설정합니다.
* update_bitmap_score 함수에서 현재 queue가 현 시점에서 가장 뛰어난 queue와 (top_rated) 비교해서 실행 시간과 data의 길이를 곱한 수보다 작으면 top_rated와 교체합니다.
* 만약 top_rated가 없을 경우, top_rated에 현재의 queue를 넣습니다.
* queue에 변화한 부분이 있었다는 (var_bytes) 표시로 flag를 설정합니다.

아래에 변형에 들어가기 전 처리 (CALIBRATION을 실패한 data가 있을 때) 의 소스 코드를 기재했습니다. calibration 함수는 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
/*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {// 3보다 작을 경우만 calibrate_case 함수를 실행

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;// 현재의 queue를 skip했으니 skip한 수를 늘린다.
      goto abandon_entry;
    }

  }
```



### 변형에 들어가기 전 처리 (data의 최소한까지 trimming)

* trim에서는 data 동작에 영향을 주지 않는 최소한까지 data의 trimming을 수행합니다. trim_case 함수가 해당 기능을 수행합니다. 아래는 trim_case 함수의 설명입니다.

* trim_case 함수에서 data의 길이를 16으로 나눈 후 계속 2씩 나눠, 최종적으로는 1024으로 나눈 곳까지 갑니다.

  이 때, run_target 함수를 실행하여 hash가 변경되는지 비교하여 변경되었다면 calibration 함수와 마찬가지로 update_bitmap_score를 갱신합니다만, 나누어 떨어질 때까지 루프를 빠지지 않으므로 현재의 trace_bits를 clean_trace에 저장합니다.

* 나누어 떨어질 때까지 나누기를 계속하므로 필연적으로 "커버리지 (trace_bits)에 변화가 있던 최소한의 길이" 까지 나누어집니다.

아래는 trimming의 소스 코드를 기재했습니다. trim_case 함수는 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
 /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);// queue를 trim하여 실행합니다.

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;// 포기한 수를 늘립니다.
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */
// 실패해도 trim_done flag를 설정합니다.
    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;// trimming하여 queue의 길이가 다르다면 변경합니다.

  }

  memcpy(out_buf, in_buf, len);// trim 되고 있다면 data의 경신를 경신합니다. (trim 되고 있지 않다면 값은 변하지 않습니다.)
```



### 변형에 들어가기 전 처리 (data의 점수화)

* performance score는 queue의 점수화를 수행하는 부분입니다. calculate_score 함수에서 점수를 매깁니다.

  아래는 calculate_score 함수의 설명입니다.

* score가 좋아지려면 4개의 조건이 있습니다.
  1. 평균 실행 시간보다 적으면 적을수록 좋은 score가 됩니다.
  2. 커버리지가 넓으면 넓을수록 좋은 score가 됩니다.
  3. queue cycle의 횟수가 높으면 높을수록 좋은 score가 됩니다. 이것은 queue가 많이 실행될수록 다양한 변형을 한 tuple에서 에러를 찾기 쉽기 때문입니다.
  4. queue의 조건 깊이가 깊을수록 좋은 score가 됩니다.

* 아래 3개의 조건 중 하나에 해당하면 skip 합니다.
  1. calculate_score가 끝나고 변형을 skip하는 (정확히는 RANDOM HAVOC 까지 goto) 조건으로 -d option가 있을 것.

  2. 이미 fuzzing 되어 있는 것. (was_fuzzed)

  3. 과거에 fuzzing 했던 (resume) favored path로 queue가 (pass_det) 남아있는 것. 

     (American Fuzzy Lop은 output 디렉토리에 과거 중단한 data를 (queue) 기록하기에, 이것을 사용하여 다시 도중부터 실행하는 기능을 가지고 있습니다. 이 data를 resume queue 라고 부릅니다. 20분 이상 실행한 흔적이 있다면 fuzzing을 처음부터 실행할 때 초기화 단계에서 경고문을 출력하고 실행이 중단됩니다.)


* skip 하지 않았을 경우, 앞으로 모든 변형을 실행하며 flag를 (doing_det) 설정합니다.

아래는 설명한 내용에 대한 소스 코드입니다. calculate_score 함수는 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);// queue의 score를 매깁니다.

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;// deterministic fuzzing flag를 설정합니다.
```



### SIMPLE BITFLIP (xor)

* SIMPLE BITFLIP에서는 bit 단위 xor, byte 단위 xor 의 2개의 방법으로 queue를 변형시킵니다.

* 먼저 bit 단위 xor의 설명입니다.

* bit 단위 xor에서는 3단계로 나누어 queue를 변형합니다.

  * 첫번째 단계에서는 1 byte를 하나의 부분에 대하여 0x80 만큼 stage 수에 더하여 left bit shift하여 xor 합니다.

  * 두번째 단계에서는 1 byte를 두개의 부분에 대하여 0x80 만큼 stage 수에 더하여 left bit shift 하여 xor 합니다.

  * 세번째 단계에서는 1 byte를 네개의 부분에 대하여 0x80 만큼 stage 수에 더하여 left bit shift 하여 xor 합니다.

    기본적인 처리는 3개 모두 같기때문에 첫 단계의 Single walking bit만을 설명하도록 하겠습니다.

* stage 마다 common_fuzz_stuff 함수가 실행되고 run_target 함수가 실행됩니다. run_target의 반환 값으로 돌아온 실행 결과를 (fault) save_if_interesting 함수를 사용하여 배분합니다. 아래는 save_if_interesting 함수의 설명입니다.

* save_if_interesting 함수를 실행하고 -C option의 (crash_mode) 경우 바로 해당 옵션 처리에 진입합니다.

  이번에는 디폴트 처리에 대해서 설명하도록 하겠습니다.

* switch문 FAULT_TMOUT, FAULT_CRASH에서 fault의 내용이 배분됩니다.
  * FAULT_TMOUT은 실행 파일이 time out 에러를 발생하고 종료한 상태입니다.
    * time out을 발생하고 종료한 전체의 수를 (total_tmouts) 증가시킵니다.
    * simplify_trace 함수를 사용하여 trace_bits의 not hit, hit의 (각각 0x01, 0x80 으로 정의되어 있습니다.) 값을 정의합니다.
    * has_new_bits를 사용하여 trace_bits와 virgin_tmout을 (time out error용의 전체 커버리지) 비교하여 발견한 적 없는 time out이 (hit count의 변경과  new tuple) 없으면 return 합니다.
    * unique time out의 수를 증가합니다. (unique_tmouts)
    * 만약 유저가 설정한 time out이 작을 경우 한 번 더 hang_tmout으로 (1000ms) run_target 함수를 실행합니다.
    * 다시 실행한 결과가 FAULT_CRASH 이라면 FAULT_CRASH의 처리로 분기합니다. FAULT_TMOUT 이라면 아무것도 하지 않고 return 합니다.
  * FAULT_CRASH은 실행 파일이 SEGV 에러를 발생시키고 종료한 상태입니다.

    처리는 FAULT_TMOUT와 다르지 않기에 생략합니다.

* SIMPLE BITFLIP에서 stage가 8의 배수 - 1 (8byte 단위) 일 때, hash를 생성하여 각각의 단계에 자동 사전형을 (a_extras) 생성합니다.
  * 현재의 stage가 가장 마지막이고, cksum과 prev_cksum이 (이전의 체크섬) 일치 할 경우에는 다음 처리에 들어갑니다.
    * out_buf의 가장 마지막 문자를 a_collect에 넣습니다.
    * a_len의 (a_collect의 길이) 길이가 3 이상 32 이하 일 경우, maybe_add_auto 함수를 실행하여 자동사전형을 (a_extras) 생성합니다.
  * cksum과 prev_cksum이 (이전의 체크섬) 일치하지 않을 때
    * a_len의 (a_collect의 길이) 길이가 3 이상 32 이하 일 경우, maybe_add_auto 함수를 실행하여 자동사전형을 (a_extras) 생성합니다.
    * prev_cksum을 cksum으로 갱신합니다.
  * 현재 queue의 cksum과 생성한 cksum을 비교하여 일치하지 않을 경우
    * a_len의 (a_collect의 길이) 길이가 32 보다 작을 경우, out_buf의 가장 마지막 문자를 a_collect에 넣습니다. a_len을 더합니다.

* 루프 처리를 빠져 나오면 Single walking bit에서 발견한 조건 분기 (queued_paths), 실행 에러를 (unique_crashes) 더합니다.

아래는 설명한 내용에 대한 소스 코드입니다. save_if_interesting 함수, simplify_trace 함수, common_fuzz_stuff 함수, maybe_add_auto 함수, 2단계 처리, 3단계 처리는 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
/*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;// len * 2^3 값을 (bit 단위) stage_max로 합니다.
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;// 실행하여 time out과 skip flag가 있으면 goto 합니다.

    FLIP_BIT(out_buf, stage_cur);
       .
       .
       .

    if (!dumb_mode && (stage_cur & 7) == 7) {// stage_cur이 (8의 배수 - 1)일 경우

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);// out_buf의 1 byte를 추가. 마지막 stage 이기에 a_len의 초기화는 하지 않습니다.

      } else if (cksum != prev_cksum) {// 이전과 체크섬이 다를 경우

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;// add했기에 a_len를 초기화 합니다.
        prev_cksum = cksum;// 체크섬의 갱신

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;// stage_flip1에서 발견한 path와 crashes의 수를 더합니다.
  stage_cycles[STAGE_FLIP1] += stage_max;// stage를 실행한 횟수를 더합니다.
```



다음은 byte 단위 xor의 설명입니다.

* byte 단위 xor에서는 1 byte 단위, 2 byte 단위, 4 byte 단위 총 3개로 queue를 변형합니다.

  이번에는 1 byte 단위만 설명하도록 하겠습니다.
* 루프에 진입하면 바로 out_buf의 1 byte를 0xff로 xor 합니다.
* common_fuzz_stuff 함수로 run_target 함수를 통하여 실행 파일을 실행합니다.
* stage마다 변형을 추가한 곳을 관리하는 곳에 (eff_map) 해당 부분이 저장되어 있지 않을 경우
  * data의 길이가 128 byte 이상 일 경우 hash을 생성합니다. (단, dumb_mode가 아닐 경우)
  * 그 이외에는 queue에 저장되어 있는 체크섬을 반전한 값을 cksum에 넣습니다.
  * cksum과 queue에 저장되어있는 체크섬이 다를 경우 eff_map에 저장하고, eff_map에 저장되어 있는 수를 (eff_cnt) 증가시킵니다.
* xor 한 out_buf의 1 byte를 원래대로 되돌립니다.
* 루프를 빠져 나오면 바로 eff_map에 저장된 수를 체크하여 수가 90% 이상 일 경우, len을 8 byte 단위로 한 상태에서 eff_map의 처음부터 다시 저장합니다.
* 8 byte 마다 저장한 수를 (blocks_eff_select) 더합니다.
* 전체의 8 byte마다 저장한 수를 (blocks_eff_total) 더합니다.

1 byte 단위 xor의 소스코드입니다. 나머지 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;// 1 byte를 0xff로 xor 합니다.

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {// 현재의 stage가 eff_map에 없을 경우

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);// 현재 queue의 길이가 128 byte 이상 일 경우
      else
        cksum = ~queue_cur->exec_cksum;// 128 byte 이상이 아닐 경우 체크섬을 반전한 값을 생성합니다.

      if (cksum != queue_cur->exec_cksum) {// 128 byte 이상에서 생성한 체크섬, 반전한 queue의 체크섬이 queue의 체크섬과 다를 경우, eff_map에 현재 stage의 flag를 설정합니다.
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;// 원래대로 되돌립니다.

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */
// 밀집한 수가 90%보다 높으면 (저장된 수가 90%보다 높으면)
  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {//len의 8 byte 단위 개수와 len AND 0x03의 값을 (len이 1 byte부터 7 byte 용) 더한 값을 eff_cnt와 비교하고,

    memset(eff_map, 1, EFF_ALEN(len));//8 byte 단위에 alignment 한 값을 eff_map 처음부터 채웁니다.

    blocks_eff_select += EFF_ALEN(len);// 채운 수만큼 더합니다.

  } else {

    blocks_eff_select += eff_cnt;// 그 이외라면 현재의 eff_cnt를 더합니다.

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;
```



### ARITHMETIC INC/DEC (수의 증가/감소)

이 변형에서는 1부터 35까지의 수를 차례로 증가・감소합니다.

* 증가・감소는 8 bit, 16 bit, 32 bit 총 3개의 방법으로 이뤄집니다.

* eff_map에 저장되어 있지 않은 곳은 이 변형을 수행하지 않습니다.

* 이전의 변형에 있던 bitflip이 되지 않았던 것에 대하여 (could_be_bitflip 함수를 사용하여 판단합니다.) 이 변형을 수행합니다.

  bitflip이 되지 않았던 것에 대해서 변형을 수행하는 이유는 이전의 bitflip 방식과 같은 data를 실행하지 않기 위해서입니다.

* 16 bit, 32 bit는 little endian과 big endian을 고려한 변형으로 되어 있습니다.

  이번에는 16 bit에서의 설명을 하겠습니다.

* data의 길이가 2 byte 미만이라면 ARITHMETIC INC/DEC 변형을 skip합니다.

* stage_max는 (루프를 실행하는 최대 횟수) 증가・감소의 little endian용과 증가・감소의 big endian용 총 4개를 최대 횟수로 설정합니다.

* out_buf를 2 byte씩 orig에 넣어 eff_map에 연속으로 저장되고 있는지 확인하고 저장되고 있지 않으면 skip합니다.

* eff_map에 저장되어 있을 경우, ARITHMETIC까지를 (1 ~ 35) 차례로 little endian과 big endian의 덧・뺄셈을 수행합니다.

* 가장 처음의 little endian

  * 증가할 때 overflow를 일으키지 않는지 체크한 후, could_be_bitflip 함수를 사용하여 bitflip이 되지 않은는지를 확인합니다. 이 조건을 충족하면 common_fuzz_stuff 함수를 실행합니다.
  * 감소할 때 underflow를 일으키지 않는지 체크한 후, could_be_bitflip 함수를 사용하여 bitflip이 되지 않았는지를 확인합니다. 이 조건을 충족하면 common_fuzz_stuff 함수를 실행합니다.

* out_buf를 원래대로 돌려놓습니다.

* 다음은 big endian입니다.

  * 처리는 little endian과 다르지 않습니다.
  * 다른 점은 SWAP함수를 사용하여 big endian으로 바꾸는 것입니다.

  아래는 16 bit의 변형입니다. 그 이외의 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 봐주시기 바랍니다.

```c
 if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;// 4는 INC/DEC의 little endian과 Big endian용

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {
// SWAP16은 little endian의 하위 1 byte 상위 1 byte를 교체합니다. (big endian용)
      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {// orig를 (2 byte) 0xff와 (하위 1 byte가 little endian이므로 상위가 됩니다.) 비교하여 overflow 하지 않는지 체크합니다.

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {// underflow를 체크합니다. 하위 1 byte가 j보다 작으면 아래를 실행합니다.

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;// 다음은 big endian으로 생각합니다.


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;
```



### INTERESTING VALUES (고정치 삽입)

INTERESTING VALUES는 고정치를 삽입하는 방법으로 8 bit, 16 bit, 32 bit의 각각 크기로 overflow, underflow, off-by-one을 비교할 때 실수할 것 같은 값을 사용하여 fuzzing을 수행합니다.

* eff_map에 저장되어 있지 않은 곳은 이 변형을 수행하지 않습니다.
* 이전 변형인 bitflip, arithmetic, interesting 이 (자신의 처리보다 작은 크기의 변형, 자기자신) 되지 않았던 것에 대하여 (could_be_bitflip 함수, could_be_arith 함수, could_be_interest 함수를 사용하여 판단합니다.) 이 변형을 수행합니다.

  되지 않았던 것에 대하여 수행하는 이유는 이전 변형과 같이 data를 실행하지 않기 위해서 입니다. (무의미함을 줄입니다.)
* 16 bit, 32 bit는 little endian과 big endian을 고려한 변형으로 되어있습니다.

이번에는 16 bit를 설명하겠습니다. 그리고 little endian과 big endian의 처리는 SWAP 함수의 사용 유무 차이이기에 little endian 부분만 설명하도록 하겠습니다.

* data의 길이가 2 byte 미만인 상태라면 변형 INTERESTING VALUES를 skip합니다.

* stage_max는 (루프를 수행하는 최대 횟수) little endian용과 big endian용 2개를 최대 횟수로 설정합니다.

  * out_buf를 2 byte씩 orig에 넣어 eff_map에 연속으로 저장되고 있는지 확인하고 저장되고 있지 않으면 skip합니다.
  * eff_map에 저장되지 않았을 경우, 이전 변형의 bitflip, arithmetic, interesting과 같은지를 확인한 후 같으면 skip합니다.
  * 같지 않으면 common_fuzz_stuff 함수를 실행합니다.

* out_buf를 원래대로 되돌립니다.

  아래는 16 bit 변형입니다. 그 이외 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 확인해주시기 바랍니다.

```c
  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);// little endian and big endian용

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {// orig이 3개가 동시에 맞지 않는 것만

        stage_val_type = STAGE_VAL_LE;// 현재 stage를 little endian으로 설정합니다.

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;
// big endian용
      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;// 원래대로 되돌립니다.

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;
```



### DICTIONARY STUFF (사전형 data 삽입)

DICTIONARY STUFF는 3개의 방식으로 이뤄집니다.

* 유저측에서 준비한 사전형 data를 사용하여 out_buf을 overwrite
* 유저측에서 준비한 사전형 data를 사용하여 out_buf을 연결 및 삽입
* 자동으로 생성한 사전형 data를 사용하여 out_buf를 overwirte

단, 유저측에서 준비한 사전형의 수와 (extras_cnt) 자동으로 생성한 사전형의 수가 (a_extras_cnt) 0 이라면 이 변형들은 각각 skip 됩니다. (기본적으로 유저측에서 사전형의 초기치를 준비하지 않았을 경우 이 변형은 수행되지 않습니다.)

우선 처음으로 유저측에서 준비한 사전형 data를 사용하여 out_buf를 overwrite 방식의 설명을 하겠습니다.

* 루프 처리는 out_buf의 len 크기가 최대 횟수로 설정됩니다. 즉, out_buf의 처음 부분부터 유저측에서 준비한 사전형 data를 사용하여 out_buf를 overwrite 합니다.

  * 다음 루프 처리는 유저측에서 준비한 사전형의 수를 최대 횟수로 설정합니다. 사전형은 미리 size 값에 정렬되어 있습니다. (초기화  단계의 load_extras 함수 부분에서 정렬됩니다.)
    * 아래 4개의 조건 중 하나에 해당되면 루프를 continue 합니다.
      1. extras_cnt가 200을 넘어도, extras_cnt를 사용해 랜덤화하여 (UR과 함께 정의되어 있습니다.) 200보다 작은 경우
      2. 사전형의 len이 out_buf len보다 클 때
      3. out_buf와 같은 값
      4. eff_map에 extras의 길이 만큼 끝부분에서 찾았을 때 falg가 하나도 설정되지 않았을 때
    * 4가지 조건에 해당되지 않을 경우, out_buf를 유저측에서 준비한 사전형 data를 사용하여 덮어쓰기 하며, common_fuzz_stuff 함수를 실행합니다. 성공하면 stage_cur을 증가합니다.

* out_buf에 in_buf를 사용하여 덮어 쓰기한 부분을 원래대로 돌려놓고, 다음 루프를 실행합니다.

  아래는 설명한 내용에 대한 소스 코드입니다. 그 이외의 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 확인해주시기 바랍니다.

```c
  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */
// extras_cnt가 200을 넘어도, extras_cnt를 사용하여 랜덤화를 합니다. 200 보다 낮을 경우 다음의 조건으로 넘어갑니다.
// 사전형의 len이 out_buf의 len보다 클 때, out_buf와 같은 값일 때, eff_map에 extras의 길이만큼 끝 부분에서 찾았을 때, 이 3개 중 하나를 만족했을 때, skip 합니다.
      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);// 원래대로 되돌립니다.

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;
```



다음으로 유저측에서 준비한 data를 사용하여 out_buf를 연결 및 삽입 방식을 설명하겠습니다.

* len + 128 byte 크기 만큼 allocate 합니다. (ex_tmp) 
* 루프 처리는 out_buf의 len 크기가 최대 횟수로 설정됩니다. 즉, out_buf의 처음부터 유저측에서 준비한 사전형 data를 사용해 out_buf에 삽입합니다.
  * 다음 루프 처리는 유저측에서 준비한 사전형의 수를 최대 횟수로 설정합니다. 사전형은 미리 size 값을 정렬합니다. (초기화 단계의 load_extras 함수의 부분에서 정렬합니다.)
    * len + extras의 길이가 1 KB 보다 클 경우, skip합니다. (작을 경우는 아래로 진행합니다.)
    * ex_tmp에 extras를 복사합니다.
    * extras를 삽입된 곳 뒤에 out_buf를 삽입합니다. (루프가 진행되면서 삽입하는 내용이 out_buf의 처음부터 하나씩 밀려들어갑니다.)
    * common_fuzz_stuff 함수를 실행합니다.
    * stage_cur을 더합니다
  * ex_tmp에 out_buf의 address를 대입합니다. (루프가 진행되면서 ex_tmp의 처음부터 out_buf로 바뀌어갑니다.)

```c
  /* Insertion of user-supplied extras. */
// 유저가 준비한 file의 data + out_buf를 직접 전부 넣는 것
  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {// 1 KB을 넘을 때
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);// 먼저 extras를 복사

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);// out_buf을 뒤에 붙입니다.

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];// out_buf을 ex_tmp의 앞에 붙입니다. (루프가 진행되면서 ex_tmp의 앞에부터 out_buf으로 바뀌어갑니다.)

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;
```



자동으로 생성한 사전형 data를 사용해 out_buf를 overwrite 하는 변형에 대한 설명은 처음 설명한 유저측에서 준비한 사전형 data를 사용해 out_buf를 overwrite 하는 변형과 같기에 생략합니다.

아래는 설명한 내용에 대한 소스 코드입니다. 그 이외의 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 확인해주시기 바랍니다.

```c
// 자동으로 생성한 것으로 out_buf의 overwrite를 수행합니다. 
  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;
```



### RANDOM HAVOC (랜덤으로 준비된 방법 선택)

RANDOM HAVOC 변형에서는 최대 16 패턴의 변형을 랜덤하게 선택하여 out_buf를 변형합니다.

RANDOM HAVOC 변형 전에 현재 queue에 (queue_cur) RANDOM HAVOC 변형까지의 변형을 끝낸 flag를 (passed_det) 설정합니다. 

이 flag로 인해 다음부터 RANDOM HAVOC 변형만으로 시작하게 됩니다. (자세히는 변형에 들어가기 전 처리 (data의 점수화)를 참조해주시기 바랍니다.)

RANDOM HAVOC 변형 설명을 하겠습니다.

* splice_cycle이 (SPLICING 변형 부분에서 flag가 설정됨) 0 일 경우 다음 처리를 합니다.

  * doing_det이 (PERFORMANCE SCORE를 수행한 flag) 설정된 경우 1024, 그 이외의 경우에는 256이 설정됩니다.

    이 값들에 perf_score를 (자세히는 변형에 들어가기 전 처리 (data의 점수화)를 참조해주시기 바랍니다.) 100과 havoc_div으로 (평균 실행 속도가 느린 것에 대하여 큰 값이 붙습니다.) 나눕니다. 그 결과를 stage_max 로 합니다.

* splice_cycle이 (SPLICING 변형 부분에서 flag가 설정됨) 0 이외의 일 경우 다음 처리를 합니다.

  * stage_max는 32 * perf_score / havoc_div / 100 이 됩니다.

* stage_max가 16보다 작을 경우 16이 됩니다.

* stage 루프 처리에 들어갑니다.

  * use_stacking은 16 패턴이 있는 변형을 몇 번 반복하는지 루프 처리 최대 값입니다. 이 값은 2 ~ 128 중 랜덤하게 선택됩니다.

  * use_stacking을 최대 값으로한 루프 처리에 들어갑니다.

    * switch문에서 사전형 data가 있으면 true로 2를 더해 0 ~ 16 범위에서 랜덤하게 선택되며, false 이면 0에서 15를 더하여 0 ~ 14 범위에서 랜덤하게 선택됩니다.
    * 아래 패턴은 out_buf가 삽입되는 곳, out_buf가 바뀌어 쓰여지는 곳, out_buf에 삽입되는 값, 선택되는 endian 등 모두 랜덤입니다.
      1. byte 단위로 bit 반전처리를 합니다.
      2. 랜덤하게 선택된 1 byte의 interesting value를 삽입
      3. 랜덤하게 선택된 2 byte의 interesting value를 랜덤하게 선택된 endian으로 삽입
      4. 랜덤하게 선택된 4 byte의 interesting value를 랜덤하게 선택된 endian으로 삽입
      5. 랜덤하게 선택된 ARITH_MAX를 1 byte의 out_buf에 감소를 수행
      6. 랜덤하게 선택된 ARITH_MAX를 1 byte의 out_buf에 증가를 수행
      7. 랜덤하게 선택된 ARITH_MAX를 2 byte의 out_buf에 랜덤하게 선택된 endian으로 감소를 수행
      8. 랜덤하게 선택된 ARITH_MAX를 2 byte의 out_buf에 랜덤하게 선택된 endian으로 증가를 수행
      9. 랜덤하게 선택된 ARITH_MAX를 4 byte의 out_buf에 랜덤하게 선택된 endian으로 감소를 수행
      10. 랜덤하게 선택된 ARITH_MAX를 4 byte의 out_buf에 랜덤하게 선택된 endian으로 증가를 수행
      11. 랜덤으로 1 - 255의 값을 사용하여 xor
      12. out_buf의 데이터를 delete
      13. 12 (or l) 와 동일
      14. out_buf에 out_buf 자신을 사용해 복사 또는 insert
      15. out_buf에 out_buf 자신을 사용해 재작성
      16. extras를 사용해 overwrite
      17. extras를 사용해 out_buf에 추가

  * use_stacking 루프를 빠져나오면 common_fuzz_stuff 함수를 실행합니다.

  * out_buf에 in_buf를 사용해 원래의 값으로 되돌립니다.

  * havoc_queued의 (초기값은 queued_paths와 동일합니다.) 값과 일치하지 않을 때 다음의 처리를 수행합니다.

    * perf_score가 havoc의 최대 스코어인 1600 이상이면 stage_max와 perf_score를 2배로 합니다.

    * havoc_queued에 queued_paths를 대입하여 값을 갱신합니다.

      아래는 설명한 내용에 대한 소스 코드를 기재했습니다. 그 이외 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 확인해주시기 바랍니다.

```c
  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {//retry_splice (havoc의 다음) 때에 flag가 설정됩니다.

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;// doin_det은 performance score를 매겨 그 후의 조건을 통과하면 매겨집니다. (기본 처음 fuzzing 된 것)
                                               // havoc_div는 평균 실행 속도가 늦으면 늦을수록 값이 큽니다.

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;// 16보다 작을 때는 가장 작은 16의 사이즈를 조정합니다.

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));// 2부터 2^7(128)까지 랜덤값

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {
// extras_cnt + a_extras_cnt가 있다면 true는 2를 더하여 0부터 16의 범위에서 랜덤화, false 라면 0을 선택 후 15를 더하여 0부터 14의 범위에서 랜덤화를 합니다.
      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {
// byte 단위로 bit 반전처리를 수행합니다. 
        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));// 1 byte 단위로 bit 반전
          break;
// 랜덤하게 선택된 1 byte의 interesting value를 삽입
        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];// 1 byte 단위의 interesting value를 랜덤하게 넣습니다.
          break;
// 랜덤하게 선택된 2 byte의 interesting value를 랜덤하게 선택된 endian으로 삽입
        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;// len이 2 byte보다 작을 경우는 종료합니다. 

          if (UR(2)) {// 1 일 경우 little endian

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];// 2 byte의 interesting value를 랜덤하게 넣습니다.

          } else {// 0 일 경우 big endian

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);// 2 byte의 interesting value를 교체하여 값을 랜덤하게 넣습니다.

          }

          break;
// 랜덤하게 선택된 4 byte의 interesting value를 랜덤하게 선택된 endian으로 삽입
        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;
// 랜덤하게 선택된 ARITH_MAX를 1 byte의 out_buf에 감소를 수행
        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;
// 랜덤하게 선택된 ARITH_MAX를 1 byte의 out_buf에 증가를 수행
        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;
// 랜덤하게 선택된 ARITH_MAX를 2 byte의 out_buf에 랜덤하게 선택된 endian으로 감소를 수행
        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;
// 랜덤하게 선택된 ARITH_MAX를 2 byte의 out_buf에 랜덤하게 선택된 endian으로 증가를 수행
        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;
// 랜덤하게 선택된 ARITH_MAX를 4 byte의 out_buf에 랜덤하게 선택된 endian으로 감소를 수행
        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;
// 랜덤하게 선택된 ARITH_MAX를 4 byte의 out_buf에 랜덤하게 선택된 endian으로 증가를 수행
        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;
// 랜덤으로 1 ~ 255 의 값을 사용하여 xor
        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;
// out_buf의 데이터를 delete
        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);// delete하는 길이를 지정, delete하는 길이는 최소 사이즈로 정합니다.

            del_from = UR(temp_len - del_len + 1);// delete 하는 처음을 랜덤으로 정합니다.

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);// del_from부터 del_len를 더한 곳으로(delete되는 가장 끝부분의 다음) del_from으로 지정합니다.

            temp_len -= del_len;// delete한 길이를 뺍니다.

            break;

          }

// out_buf에 out_buf 자신을 사용해 복사 또는 insert
        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {// 1 KB를 넘지 않았을 때

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {// 1,2,3 일 때

              clone_len  = choose_block_len(temp_len);// clone할 길이를 선정합니다.
              clone_from = UR(temp_len - clone_len + 1);// clone할 처음을 선정합니다.

            } else {// 0 일 때는 강제로 block 단위의 insert가 됩니다.

              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to   = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);// 복사
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);// insert

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);// 복사 또는 insert한 다음 부분에 out_buf의 clone 다음의 남은 값을 넣습니다.

            ck_free(out_buf);
            out_buf = new_buf;// out_buf의 버튼을 new_buf로 설정합니다.
            temp_len += clone_len;// clone한 길이만큼 더합니다.

          }

          break;
// out_buf에 out_buf 자신을 사용해 재작성
        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {// 75%의 확률로 out_buf 의 값을 사용하여 재작성됩니다.

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);// 25%의 확률로 이쪽으로 되어있으며 50%의 확률로 0xff로 바뀌어 재작성됩니다.

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */
// extras를 사용해 overwrite
        case 15: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {// extras가 없을 때 또는 자동 extras가 1과 AND 일 때

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {// extras가 있을 때 또는 자동 extras가 0과 AND 일 때

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);// insert_at의 부분부터 바꿔 작성합니다.

            }

            break;

          }
// extras를 사용해 out_buf에 추가
        case 16: {

            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);// out_uf의 랜덤한 길이
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {// extras가 없을 때 또는 자동 extras가 1과 AND 일 때

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);// out_buf의 처음부터 insert_at까지의 길이를 new_buf에 복사합니다.

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);// 뒤에 extras를 삽입합니다.

            } else {// extras가 있을 때 또는 자동 extras가 0과 AND 일 때

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);// 뒤에 extras를 삽입합니다.

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);// out_buf의 나머지를 extras의 뒤에 붙입니다.

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);// out_buf를 원래대로 되돌립니다.

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {// havoc_queued의 (초기값은 queued_paths와 동일) 값과 일치하지 않을 때

      if (perf_score <= HAVOC_MAX_MULT * 100) {// HAVOC의 최대 스코어보다 perf_score가 작을 경우
        stage_max  *= 2;// stage를 2배로 길게 합니다.
        perf_score *= 2;// score를 2배로 길게 합니다.
      }

      havoc_queued = queued_paths;// queued_paths가 증가하므로 수를 경신합니다.

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }
```



### SPLICING (data splite) 

* 아래 4개의 조건에 해당되어야 SPLICING 변형에 진입할 수 있습니다.
  1. use_spliceing은 -M option (force_deterministic flag가 설정되지 않았을 때) 이외에는 flag가 설정되어 있을 것.
  2. splice_cycle과 비교하여 spliceing하는 최대횟수인 14회보다 적을 것. (이 때는 splice_cycle이 증가합니다.)
  3. queue와 현재 queue의 길이가 2 byte 이상이어야 할 것.
  4. queue의 수가 (queue_paths) 1보다 많을 것.


* in_buf와 orig_in의 address가 일치하지 않을 경우 현재의 in_buf를 해제하여 orig_in과 같은 address로 합니다.
* 적당히 queue된 test case를 불러옵니다. 이 때, 현재의 test case와 일치하면 같은 처리를 한 번 더 수행합니다.
* splicing_with에 적당히 불러온 queue를 (tid) 넣습니다. 또, target에 처음의 queue를 넣습니다.
* tid가 100을 넘기고 있다면 현재 queue부터 시작하여 next_100으로 100개씩 증가합니다. (이 때 tid에서 100이 감소됩니다.) 다음으로 tid가 0가 될 때까지 next로 하나씩 증가합니다. 최종 queue에 다다르기까지 증가합니다.
* target의 길이가 2 byte보다 아래, 또는 현재의 queue인 경우에는 다음의 target으로 하여 splicing_with를 더합니다.
* target이 없을 경우에는 처음부터 SPLICING 변형을 다시 수행합니다.
* target의 data를 new_buf에 복사합니다.
* locate_diffs 함수를 사용하여 in_buf와 new_buf를 처음부터 비교하여 가장 처음으로 다른 byte와 (f_diff) 가장 마지막으로 다른 byte를 (l_diff) 얻어옵니다.
* f_diff와 l_diff가 split이 가능하지 않은 길이라면 처음부터 SPLICING 변형을 다시 수행합니다.
* splite_at에 f_diff + l_diff와 f_diff의 등급을 두어 랜덤하게 선택한 후 그 값을 대입합니다.
* new_buf의 처음부터 in_buf의 내용을 splite_at의 길이만큼 복사합니다.
* in_buf에 new_buf의 address를 대입합니다.
* out_buf의 메모리를 해제한 후 다시 target의 길이만큼 allocate하고, out_buf에 in_buf의 (실질적인 new_buf의 내용) 내용을 복사합니다.
* RANDOM HAVOC 변형을 수행합니다.

아래는 설명한 내용에 대한 소스 코드를 기재했습니다. 그 이외 부분은 [GitHub](https://github.com/syarochan/public_study)에 공개한 소스 코드를 확인해주시기 바랍니다.
```c
#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:
// use_spliceing은 -M option(force_deterministic flag가 설정되어 있지 않을 때)이외일 때 사용됩니다.
// spliceing하는 최대횟수는 14회
// queue와 현재 queue의 길이가 2 byte 이상이어야 합니다.
  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {// address가 일치하지 않을 경우 현재의 in_buf를 해제하여 원래대로 되돌립니다.
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */
// 적당히 queue된 test case를 불러옵니다. 이 때, 현재의 test case와 일치하면 한 번 더 불러옵니다.
    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;
// tid가 100을 넘는다면 현재 queue부터 next_100을 따라갑니다. 다음으로 tid가 0 될 때까지 next를 따라갑니다. 그리고 최종 tid의 queue에 도착합니다.
    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */
// target의 길이가 2 byte보다 아래 또는, 현재 queue인 경우 다음의 target으로 옮깁니다.
    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;// target가 없을 경우 한 번 더 처음부터 시작합니다.

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */
// in_buf와 new_buf의 가장 처음에 다른 byte와 가장 마지막에 다른 byte를 가져옵니다.
    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {// split이 되지 않는 길이라면
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);// split의 길이를 결정합니다.

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);// new_buf에 split한 길이만큼 복사합니다.
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);// out_buf에 target queue의 길이만큼 out_buf에 복사합니다.

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */
```



지금까지 fuzz_one 함수의 설명이었습니다.

여유가 생긴다면 undocument 부분도 작성하고 싶지만 피곤하기에 이번 글은 이 정도에서 글을 줄이겠습니다.

다음은 (만약 있다면) 메모리 관련, undocument 부분, 병행 처리 관련에 대하여 작성할 생각입니다.
