
import sys
import os
import time
import json
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import auth_client as AUTH
import link_generator as LG

FALLBACK_SERVICES = [3]
MAX_ROUNDS = 3
OAUTH_LOCK_MARKERS = (
    'account-unlock-required',
    'unlock this session',
    'please verify with google or discord',
)
OAUTH_ERROR = "该链接需要先完成 Google/Discord 验证解锁后才能解卡（打开链接完成验证后重发即可）"


def is_oauth_lock(r):
    if not isinstance(r, dict):
        return False
    if r.get('code') == 'account-unlock-required' or r.get('oauth_required') is True:
        return True
    msg = ' '.join(str(r.get(k, '')) for k in ('message', 'error', 'code', 'detail')).lower()
    return any(m in msg for m in OAUTH_LOCK_MARKERS)

MAX_ROUNDS_HARD_CAP = 12     # 12 轮，防死循环
POLL_MAX_ATTEMPTS = 10       # about:blank 后轮询 key 的次数
POLL_INTERVAL = 0.1          # 每次轮询间隔(秒)
POLL_OVERLAP_DELAY = 0.05    # step 发出后多久开始并发轮询 key(重叠掉一个 RTT)
STEP_THROTTLE_RETRIES = 2    # 遇到限流时重试次数
STEP_THROTTLE_SLEEP = 2.0    # 限流退避休眠(秒)
MIN_STEP_GAP = 5.0           # 相邻两次 step 的最小间隔(秒)


class Timer:
    def __init__(self):
        self.phases = {}  # 阶段名 -> 总秒数
        self.t0 = None
        self.current_phase = None
        self.invalid_reason = None   # 若求解因"无效/过期链接"终止,记录上游原因
        self.oauth_locked = False
        self.result_ticket = None


    def start(self, phase):
        if self.current_phase is not None:
            self.stop()
        self.current_phase = phase
        self.t0 = time.time()

    def stop(self):
        if self.current_phase is not None and self.t0 is not None:
            dt = time.time() - self.t0
            self.phases[self.current_phase] = self.phases.get(self.current_phase, 0.0) + dt
            self.current_phase = None
            self.t0 = None

    def add(self, name, seconds):
        self.phases[name] = self.phases.get(name, 0.0) + seconds

    def total(self):
        return sum(self.phases.values())

    def summary(self):
        parts = []
        for name, secs in sorted(self.phases.items(), key=lambda x: -x[1]):
            pct = secs / self.total() * 100 if self.total() > 0 else 0
            parts.append(f"    {name}: {secs:.1f}s ({pct:.0f}%)")
        return '\n'.join(parts)

    def __repr__(self):
        return f"Timer({self.total():.1f}s total, {len(self.phases)} phases)"




def resolve_service(ticket, session=None, verbose=True):
    svc, cp, valid, reason = resolve_meta(ticket, session=session, verbose=verbose)
    return svc, cp


def resolve_meta(ticket, session=None, verbose=True):
    """一次 metadata 调用同时得到 (service, checkpointCount, valid, invalid_reason)
    """
    cp = None
    try:
        meta = AUTH.get_session_metadata(ticket, session=session)
        if isinstance(meta, dict):
            if meta.get('success') is False and not meta.get('transient'):
                msg = str(meta.get('message') or meta.get('error') or '').lower()
                if any(m in msg for m in AUTH.INVALID_MARKERS):
                    reason = str(meta.get('message') or meta.get('error') or 'invalid link')
                    if verbose:
                        print(f'  [meta] 无效链接: {reason}', flush=True)
                    return None, cp, False, reason
            data = meta.get('data', meta)
            if isinstance(data, dict):
                profile = data.get('activeRevenueProfile', {})
                if isinstance(profile, dict) and 'service' in profile:
                    svc = int(profile['service'])
                    try:
                        cpn = profile.get('checkpointCount')
                        cp = int(cpn) if cpn else None
                    except (TypeError, ValueError):
                        cp = None
                    if verbose:
                        dur = data.get('duration', '?')
                        print(f'  [meta] service={svc} checkpointCount={cp} duration={dur}h', flush=True)
                    return svc, cp, True, None
    except Exception as e:
        if verbose:
            print(f'  [meta] 获取失败: {e}', flush=True)
    return None, cp, True, None


def throttled(r):
    if not isinstance(r, dict):
        return False
    msg = ' '.join(str(r.get(k, '')) for k in ('message', 'error', 'detail')).lower()
    return ('too fast' in msg) or ('slow down' in msg) or ('too many' in msg)


def do_step_with_retry(ticket, service=None, session=None, verbose=True, timer=None,
                       gap_state=None, overlap_poll=False, poll_session=None):
    services_to_try = []
    if service is not None:
        services_to_try.append(service)
    for svc in FALLBACK_SERVICES:
        if svc not in services_to_try:
            services_to_try.append(svc)

    if timer:
        timer.start('step')

    if gap_state is not None and gap_state.get('ts'):
        gap = time.time() - gap_state['ts']
        if gap < MIN_STEP_GAP:
            if verbose:
                print(f'  [step] 距上次 step 仅 {gap:.1f}s，等待 {MIN_STEP_GAP - gap:.1f}s...', flush=True)
            time.sleep(MIN_STEP_GAP - gap)

    overlap_box = {}
    overlap_thread = None

    def overlap_poll_worker():
        time.sleep(POLL_OVERLAP_DELAY)
        sess = poll_session if poll_session is not None else session
        for _ in range(POLL_MAX_ATTEMPTS):
            if overlap_box.get('stop'):
                return
            try:
                st = AUTH.get_session_status(ticket, session=sess)
                data = st.get('data', st) if isinstance(st, dict) else {}
                k = data.get('key', '')
                if k and k != 'KEY_NOT_FOUND':
                    overlap_box['key'] = k
                    return
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    for svc in services_to_try:
        for attempt in range(STEP_THROTTLE_RETRIES + 1):
            try:
                t0 = time.time()
                if overlap_poll and overlap_thread is None:
                    overlap_thread = threading.Thread(target=overlap_poll_worker, daemon=True)
                    overlap_thread.start()
                r = AUTH.do_step(ticket, service=svc, session=session)
                dt = time.time() - t0
                if gap_state is not None:
                    gap_state['ts'] = time.time()
                if isinstance(r, dict) and r.get('success'):
                    if timer:
                        timer.stop()
                    if verbose:
                        print(f'  [step] service={svc} -> 成功 ({(dt * 1000):.0f}ms)', flush=True)
                    return svc, r, overlap_box
                if is_oauth_lock(r):
                    if timer:
                        timer.stop()
                        timer.oauth_locked = True
                    if verbose:
                        print(f'  [lock] Discord/Google 锁定，停止重试 ({(dt * 1000):.0f}ms)', flush=True)
                    overlap_box['stop'] = True
                    return None, r, overlap_box
                if throttled(r):
                    if attempt < STEP_THROTTLE_RETRIES:
                        if verbose:
                            print(f'  [step] service={svc}: 限流，退避 {STEP_THROTTLE_SLEEP}s 后重试'
                                  f' ({attempt + 1}/{STEP_THROTTLE_RETRIES})', flush=True)
                        time.sleep(STEP_THROTTLE_SLEEP)
                        continue
                if verbose:
                    err = json.dumps(r)[:200] if isinstance(r, dict) else str(r)[:200]
                    print(f'  [step] service={svc}: {err} ({(dt * 1000):.0f}ms)', flush=True)
                break
            except Exception as e:
                if verbose:
                    print(f'  [step] service={svc} 异常: {e}', flush=True)
                break

    if timer:
        timer.stop()
    overlap_box['stop'] = True
    return None, {'success': False, 'error': 'all services failed'}, overlap_box


def check_key_in_response(ticket, session=None, verbose=True, timer=None):
    try:
        if timer:
            timer.start('poll')
        st = AUTH.get_session_status(ticket, session=session)
        if timer:
            timer.stop()
        st_data = st.get('data', st) if isinstance(st, dict) else {}
        key = st_data.get('key', '')
        if key and key != 'KEY_NOT_FOUND':
            if verbose:
                print(f'  [key] 发现 KEY: {key}', flush=True)
            return key
        if verbose and key:
            print(f'  [key] 尚未就绪: {key}', flush=True)
    except Exception as e:
        if verbose:
            print(f'  [key] 检查异常: {e}', flush=True)
    return None


def poll_for_key(ticket, session=None, max_attempts=3, interval=0, verbose=True, timer=None):
    for i in range(max_attempts):
        key = check_key_in_response(ticket, session=session, verbose=verbose, timer=timer)
        if key:
            return key
        if interval > 0 and i < max_attempts - 1:
            time.sleep(interval)
    return None


def solve_chain(ticket, verbose=True, max_rounds=MAX_ROUNDS, session=None):
    if session is None:
        session = AUTH.create_session()
    current_ticket = ticket
    current_service = None
    timer = Timer()
    timer.result_ticket = current_ticket
    invalid_reason = [None]
    round_cap = max(max_rounds, 1)
    round_idx = 0
    last_exit = ['round-exhausted']
    gap_state = {'ts': 0.0}

    while round_idx < round_cap:
        if verbose:
            print(f'  [{round_idx + 1}/{round_cap}]', flush=True)
        cpc = None
        if round_idx == 0:
            if timer:
                timer.start('meta')
            meta_session = AUTH.create_session()
            meta_future = None
            stat_future = None
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    meta_future = pool.submit(resolve_meta, current_ticket, meta_session, verbose)
                    stat_session = AUTH.create_session()
                    stat_future = pool.submit(check_key_in_response, current_ticket,
                                              stat_session, verbose, None)
                    try:
                        early = stat_future.result(timeout=6)
                    except Exception:
                        early = None
                    if early:
                        if verbose:
                            print(f'  [early] 该链接已完成，直接返回已有 KEY', flush=True)
                        return early, timer
                    try:
                        svc, cpc, mvalid, mreason = meta_future.result(timeout=6)
                        current_service = svc
                        if not mvalid:
                            invalid_reason[0] = mreason
                            last_exit[0] = 'invalid-link'
                            timer.invalid_reason = mreason
                            return None, timer
                    except Exception:
                        current_service, cpc = None, None
            finally:
                meta_session.close()
                try:
                    stat_session.close()
                except Exception:
                    pass
            if timer:
                timer.stop()

        if cpc is not None:
            need = cpc + 1
            if need > round_cap:
                round_cap = min(need, MAX_ROUNDS_HARD_CAP)
                if verbose:
                    print(f'  [rounds] checkpointCount={cpc} -> 需 {need} 轮 (当前 cap={round_cap})', flush=True)

        if current_service is not None and verbose:
            print(f'  [service] metadata: {current_service}', flush=True)

        last_step = round_idx > 0
        service, resp, overlap = do_step_with_retry(
            current_ticket,
            service=current_service,
            session=session,
            verbose=verbose,
            timer=timer,
            gap_state=gap_state,
            overlap_poll=last_step,
            poll_session=None
        )
        if overlap.get('key'):
            if verbose:
                print(f'  [key] 发现 KEY (重叠轮询): {overlap["key"]}', flush=True)
            return overlap['key'], timer
        if service is None:
            if is_oauth_lock(resp) or getattr(timer, 'oauth_locked', False):
                confirmed = check_key_in_response(current_ticket, session=session, verbose=verbose, timer=timer)
                if confirmed:
                    return confirmed, timer
                timer.oauth_locked = True
                timer.invalid_reason = 'account-unlock-required'
                last_exit[0] = 'oauth-lock'
                if verbose:
                    print(OAUTH_ERROR, flush=True)
                return None, timer
            if verbose:
                print(f'  [-] 第 {round_idx + 1} round step 全部失败, 跳过', flush=True)
            last_exit[0] = 'step-failed'
            round_idx += 1
            continue

        current_service = service
        if resp.get('already_exists') and verbose:
            print(f'  [step] identifier 已有 key，改走 status 轮询', flush=True)
        url = (resp.get('data') or {}).get('url', '')
        if not url:
            if verbose:
                print(f'  [-] 响应中没有 URL', flush=True)
            last_exit[0] = 'no-url'
            round_idx += 1
            continue

        if verbose:
            url_short = url[:80] + '...' if len(url) > 80 else url
            print(f'  [url] {url_short}', flush=True)

        if url == 'about:blank':
            if verbose:
                print(f'  [poll] (about:blank) 轮询 key, 最多 {POLL_MAX_ATTEMPTS} 次/每次{POLL_INTERVAL}s...', flush=True)
            key = poll_for_key(current_ticket, session=session, verbose=verbose, timer=timer,
                               max_attempts=POLL_MAX_ATTEMPTS, interval=POLL_INTERVAL)
            if key:
                return key, timer
            if verbose:
                print(f'  [-] 轮询 {POLL_MAX_ATTEMPTS} 次仍未拿到 key', flush=True)
            last_exit[0] = 'poll-timeout'
            round_idx += 1
            continue

        callback = AUTH.decode_callback_url(url)
        if callback:
            next_ticket = AUTH.extract_ticket_from_callback(callback)
            if next_ticket and len(next_ticket) > 50:
                if verbose:
                    print(f'  [next] 新 ticket: {next_ticket[:24]}... ({len(next_ticket)} chars)', flush=True)
                current_ticket = next_ticket
                timer.result_ticket = current_ticket
                round_idx += 1
                continue

        if verbose:
            print(f'  [info] 无 r= 回调, 尝试轮询 key...', flush=True)
        key = check_key_in_response(current_ticket, session=session, verbose=verbose, timer=timer)
        if key:
            return key, timer
        last_exit[0] = 'no-callback-no-key'
        break

    key = check_key_in_response(current_ticket, session=session, verbose=verbose, timer=timer)
    if key:
        return key, timer

    if verbose:
        print(f'\n[-] 未获取到 key (原因: {last_exit[0]}; 已跑 {round_idx}/{round_cap} 轮)', flush=True)
    return None, timer


def solve_fresh(verbose=True, max_rounds=MAX_ROUNDS):
    """随机 identifier 开票再求解。当前新 HWID 一般不触发 Discord。"""
    urls = LG.batch_links(1)
    if not urls:
        raise RuntimeError('fresh generate returned no url')
    url = urls[0]
    ticket = AUTH.extract_ticket(url)
    if verbose:
        print(f'  [fresh] {url[:88]}...', flush=True)
    return solve_chain(ticket, verbose=verbose, max_rounds=max_rounds), url


def main():
    ap = argparse.ArgumentParser(
        description='Delta自动求解器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''示例:
  %(prog)s "https://auth.platorelay.com/a?d=<ticket>"
  %(prog)s "<raw_ticket>"
  %(prog)s ticket.txt
  %(prog)s --generate 3
        '''
    )
    ap.add_argument('target', nargs='?', help='auth URL / ticket / 文件路径')
    ap.add_argument('--generate', '-g', type=int, default=0,
                    help='通过 Platoboost API 生成 N 条测试链接')
    ap.add_argument('--quiet', '-q', action='store_true',
                    help='静默模式 (只输出结果)')
    ap.add_argument('--max-rounds', type=int, default=MAX_ROUNDS,
                    help=f'最大 round 数 (默认 {MAX_ROUNDS})')
    ap.add_argument('--no-auto', action='store_true',
                    help='只生成链接, 不求解')
    ap.add_argument('--fresh', dest='fresh', action='store_true', default=True,
                    help='锁票时自动换新 identifier 求解（默认开）')
    ap.add_argument('--no-fresh', dest='fresh', action='store_false',
                    help='锁票不换 HWID，卡在 Discord 就失败')
    args = ap.parse_args()

    verbose = not args.quiet

    AUTH.start_version_watcher()

    tickets = []
    gen_start = time.time()

    if args.generate > 0:
        if verbose:
            print(f'[*] 生成 {args.generate} 条链接...', flush=True)
        try:
            urls = LG.batch_links(args.generate)
            tickets = [AUTH.extract_ticket(u) for u in urls]
            if verbose:
                print(f'[*] 成功获取 {len(tickets)} 条 ticket', flush=True)
        except Exception as e:
            print(f'[-] 生成链接失败: {e}', file=sys.stderr, flush=True)
            sys.exit(1)
    elif args.target:
        tickets.append(AUTH.extract_ticket_from_arg(args.target))
    else:
        ap.print_help()
        sys.exit(1)

    if args.no_auto:
        for t in tickets:
            print(f'https://auth.platorelay.com/a?d={t}')
        return

    results = []
    for i, ticket in enumerate(tickets):
        t0 = time.time()
        key, timer = solve_chain(ticket, verbose=verbose, max_rounds=args.max_rounds,
                                 session=None)
        if (not key) and getattr(timer, 'oauth_locked', False):
            if verbose:
                print(OAUTH_ERROR, flush=True)
        dt = time.time() - t0
        results.append((i, key, timer, dt))

        if key:
            print(f'\n{"=" * 60}', flush=True)
            print(f'[+] DELTA KEY #{i + 1}: {key}', flush=True)
            print(f'[+] 耗时: {dt:.1f}s', flush=True)
            print(f'[+] 阶段明细:')
            print(timer.summary())
            print(f'{"=" * 60}', flush=True)
        elif verbose:
            print(f'\n[-] 链接 {i + 1}: 未获取到 key', flush=True)
            if timer.total() > 0:
                print(f'[-] 耗时: {dt:.1f}s')
                print(f'[-] 阶段明细:')
                print(timer.summary())

    total_elapsed = time.time() - gen_start
    success_count = sum(1 for _, key, _, _ in results if key)
    total_timer = Timer()
    for _, _, timer, _ in results:
        for name, secs in timer.phases.items():
            total_timer.add(name, secs)

    print(f'\n{"=" * 60}', flush=True)
    print(f'[+] 汇总: {success_count}/{len(tickets)} 成功', flush=True)
    print(f'[+] 总耗时: {total_elapsed:.1f}s', flush=True)
    if len(tickets) > 0:
        print(f'[+] 平均每链接: {total_elapsed / len(tickets):.1f}s', flush=True)
    if total_timer.total() > 0:
        print(f'[+] 总阶段明细:')
        print(total_timer.summary())
    print(f'{"=" * 60}', flush=True)


if __name__ == '__main__':
    main()
