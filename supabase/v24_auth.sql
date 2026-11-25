-- v24 계정 비밀번호 + 로그인 세션
-- 지금까지는 닉네임만 알면 그 계정으로 들어갈 수 있었어요. 이제 계정마다 비밀번호가 있고,
-- 로그인하면 서버가 세션 토큰을 발급해요(브라우저에 저장 → 다음부터 자동 로그인).
-- 돈·무기 저장, 경매, 레이드 보상, 원자폭탄 구매는 전부 "이름 + 세션 토큰"이 맞아야만 처리돼요.
--
-- ⚠ 이 파일을 적용하면 옛 클라이언트(v23 이하)는 저장·경매·레이드·원자폭탄 구매가 안 돼요.
--    index.html(v24)과 admin.html을 같이 배포하세요. 여러 번 실행해도 안전해요(idempotent).
--
-- 기존 계정(비밀번호 없음)은 "처음 로그인하는 사람이 비밀번호를 정해서 가져가는" 방식이에요.
-- 아는 사람 계정은 관리자 페이지에서 먼저 비밀번호를 걸어 두면 가로채기를 막을 수 있어요.

create extension if not exists pgcrypto with schema extensions;

alter table public.cc_profiles add column if not exists pw_hash text;

-- ---------------------------------------------------------------- 세션 / 실패 기록 (직접 접근 불가)
create table if not exists public.cc_sessions (
  token_hash text primary key,
  name       text not null,
  created_at timestamptz not null default now(),
  last_seen  timestamptz not null default now()
);
create index if not exists cc_sessions_name_idx on public.cc_sessions (name);
alter table public.cc_sessions enable row level security;
revoke all on public.cc_sessions from anon, authenticated;

create table if not exists public.cc_login_fails (
  name         text primary key,
  fails        int not null default 0,
  locked_until timestamptz,
  last_at      timestamptz not null default now()
);
alter table public.cc_login_fails enable row level security;
revoke all on public.cc_login_fails from anon, authenticated;

-- ---------------------------------------------------------------- 내부 도우미 (외부 호출 불가)
create or replace function public.cc_name_ok(n text) returns boolean
language sql immutable set search_path to 'public' as $$
  select n is not null and n = btrim(n) and char_length(n) between 1 and 12
     and n !~ '^게스트[0-9]{4}$' and left(n, 1) <> '[' and n !~ '[[:cntrl:]]'
$$;

create or replace function public.cc_pw_ok(p text) returns boolean
language sql immutable set search_path to 'public' as $$
  select p is not null and char_length(p) between 4 and 64
$$;

create or replace function public.cc_is_banned(n text) returns text
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare r text;
begin
  if to_regclass('public.cc_bans') is null then return null; end if;
  execute 'select coalesce(reason, '''') from public.cc_bans where name = $1' into r using n;
  return r;   -- null = 차단 아님
end $$;

-- 새 세션 발급 (토큰 원문은 여기서만 만들고 DB에는 해시만 저장, 계정당 최대 10개)
create or replace function public.cc_new_session(p_name text) returns text
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare t text := encode(extensions.gen_random_bytes(24), 'hex');
begin
  insert into public.cc_sessions (token_hash, name) values (encode(extensions.digest(t, 'sha256'), 'hex'), p_name);
  delete from public.cc_sessions where name = p_name and token_hash not in
    (select token_hash from public.cc_sessions where name = p_name order by last_seen desc limit 10);
  if random() < 0.02 then delete from public.cc_sessions where last_seen < now() - interval '90 days'; end if;
  return t;
end $$;

-- 이름 + 토큰이 맞고, 계정이 아직 있으면 true (90일 안 쓰면 만료)
create or replace function public.cc_auth_ok(p_name text, p_token text) returns boolean
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare h text;
begin
  if p_name is null or p_token is null or length(p_token) < 20 then return false; end if;
  h := encode(extensions.digest(p_token, 'sha256'), 'hex');
  perform 1 from public.cc_sessions where token_hash = h and name = p_name and last_seen > now() - interval '90 days';
  if not found then return false; end if;
  perform 1 from public.cc_profiles where name = p_name;
  if not found then return false; end if;
  update public.cc_sessions set last_seen = now() where token_hash = h and last_seen < now() - interval '1 hour';
  return true;
end $$;

-- 비밀번호 확인 + 실패 횟수 제한 (5번 틀리면 1분, 10번 이상이면 5분 잠금)
create or replace function public.cc_pw_verify(p_name text, p_pw text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare h text; f public.cc_login_fails%rowtype; n int;
begin
  select * into f from public.cc_login_fails where name = p_name;
  if found and f.locked_until is not null and f.locked_until > now() then
    return jsonb_build_object('ok', false, 'err', 'locked', 'wait', ceil(extract(epoch from f.locked_until - now()))::int);
  end if;
  select pw_hash into h from public.cc_profiles where name = p_name;
  if not found then return jsonb_build_object('ok', false, 'err', 'no_account'); end if;
  if h is null then return jsonb_build_object('ok', false, 'err', 'need_pw'); end if;
  if p_pw is not null and h = extensions.crypt(p_pw, h) then
    delete from public.cc_login_fails where name = p_name;
    return jsonb_build_object('ok', true);
  end if;
  insert into public.cc_login_fails (name, fails, last_at) values (p_name, 1, now())
    on conflict (name) do update set fails = case when public.cc_login_fails.last_at < now() - interval '1 hour' then 1 else public.cc_login_fails.fails + 1 end, last_at = now()
    returning fails into n;
  if n >= 5 then update public.cc_login_fails set locked_until = now() + case when n >= 10 then interval '5 minutes' else interval '1 minute' end where name = p_name; end if;
  return jsonb_build_object('ok', false, 'err', 'bad_pw', 'left', greatest(0, 5 - n));
end $$;

revoke all on function public.cc_name_ok(text), public.cc_pw_ok(text), public.cc_is_banned(text), public.cc_new_session(text),
  public.cc_auth_ok(text, text), public.cc_pw_verify(text, text) from public, anon, authenticated;

-- ---------------------------------------------------------------- 게임이 부르는 함수
-- 이 닉네임이 있는지 / 비밀번호가 걸려 있는지 (로그인 화면용)
create or replace function public.cc_account_status(p_name text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare h text; found_ boolean;
begin
  select pw_hash into h from public.cc_profiles where name = p_name; found_ := found;
  return jsonb_build_object('exists', found_, 'has_pw', h is not null);
end $$;

-- 새 계정 만들기 (게스트로 하던 진행을 그대로 이어받음)
create or replace function public.cc_register(p_name text, p_pw text, p_money bigint, p_own jsonb) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare t text;
begin
  if not public.cc_name_ok(p_name) then return jsonb_build_object('ok', false, 'err', 'bad_name'); end if;
  if not public.cc_pw_ok(p_pw) then return jsonb_build_object('ok', false, 'err', 'bad_pw_fmt'); end if;
  if public.cc_is_banned(p_name) is not null then return jsonb_build_object('ok', false, 'err', 'banned'); end if;
  perform 1 from public.cc_profiles where name = p_name;
  if found then return jsonb_build_object('ok', false, 'err', 'exists'); end if;
  begin
    insert into public.cc_profiles (name, money, own, pw_hash, updated_at)
    values (p_name, greatest(0, coalesce(p_money, 0)), case when jsonb_typeof(p_own) = 'object' then p_own else '{}'::jsonb end,
            extensions.crypt(p_pw, extensions.gen_salt('bf', 8)), now());
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'err', 'exists');
  end;
  t := public.cc_new_session(p_name);
  return jsonb_build_object('ok', true, 'token', t);
end $$;

-- 로그인
create or replace function public.cc_login(p_name text, p_pw text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare v jsonb; why text;
begin
  if p_name is null or char_length(p_name) > 12 then return jsonb_build_object('ok', false, 'err', 'no_account'); end if;
  v := public.cc_pw_verify(p_name, p_pw);
  if not (v ->> 'ok')::boolean then return v; end if;
  why := public.cc_is_banned(p_name);
  if why is not null then return jsonb_build_object('ok', false, 'err', 'banned', 'reason', why); end if;
  return jsonb_build_object('ok', true, 'token', public.cc_new_session(p_name));
end $$;

-- 비밀번호가 없는 옛 계정: 처음 가져가는 사람이 비밀번호를 정해요
create or replace function public.cc_claim(p_name text, p_pw text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare n int; why text;
begin
  if not public.cc_pw_ok(p_pw) then return jsonb_build_object('ok', false, 'err', 'bad_pw_fmt'); end if;
  why := public.cc_is_banned(p_name);
  if why is not null then return jsonb_build_object('ok', false, 'err', 'banned', 'reason', why); end if;
  update public.cc_profiles set pw_hash = extensions.crypt(p_pw, extensions.gen_salt('bf', 8)) where name = p_name and pw_hash is null;
  get diagnostics n = row_count;
  if n = 0 then return jsonb_build_object('ok', false, 'err', 'not_claimable'); end if;
  return jsonb_build_object('ok', true, 'token', public.cc_new_session(p_name));
end $$;

create or replace function public.cc_logout(p_token text) returns boolean
language plpgsql security definer set search_path to 'public', 'extensions' as $$
begin
  if p_token is null then return false; end if;
  delete from public.cc_sessions where token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex');
  return true;
end $$;

-- 비밀번호 변경 (현재 비밀번호 필요 · 변경하면 다른 기기는 로그아웃)
create or replace function public.cc_set_password(p_name text, p_token text, p_old text, p_new text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare v jsonb;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if not public.cc_pw_ok(p_new) then return jsonb_build_object('ok', false, 'err', 'bad_pw_fmt'); end if;
  v := public.cc_pw_verify(p_name, p_old);
  if not (v ->> 'ok')::boolean then return v; end if;
  update public.cc_profiles set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 8)) where name = p_name;
  delete from public.cc_sessions where name = p_name and token_hash <> encode(extensions.digest(p_token, 'sha256'), 'hex');
  return jsonb_build_object('ok', true);
end $$;

-- 닉네임 변경 (로그인 상태에서만 · 계정 데이터·세션·열린 경매가 같이 따라와요)
create or replace function public.cc_rename(p_name text, p_token text, p_new text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if not public.cc_name_ok(p_new) then return jsonb_build_object('ok', false, 'err', 'bad_name'); end if;
  if p_new = p_name then return jsonb_build_object('ok', false, 'err', 'same'); end if;
  if public.cc_is_banned(p_new) is not null then return jsonb_build_object('ok', false, 'err', 'banned'); end if;
  perform 1 from public.cc_profiles where name = p_new;
  if found then return jsonb_build_object('ok', false, 'err', 'exists'); end if;
  begin
    update public.cc_profiles set name = p_new, updated_at = now() where name = p_name;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'err', 'exists');
  end;
  update public.cc_sessions set name = p_new where name = p_name;
  if to_regclass('public.cc_auctions') is not null then
    execute 'update public.cc_auctions set seller = $1 where seller = $2 and status = ''open''' using p_new, p_name;
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- 내 돈·무기 불러오기 / 저장 / 관리자 수정 확인 (cc_profiles 직접 접근 대신)
create or replace function public.cc_load(p_name text, p_token text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare r public.cc_profiles%rowtype;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into r from public.cc_profiles where name = p_name;
  return jsonb_build_object('ok', true, 'money', r.money, 'own', coalesce(r.own, '{}'::jsonb), 'adm_seq', r.adm_seq);
end $$;

create or replace function public.cc_save(p_name text, p_token text, p_money bigint, p_own jsonb) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if jsonb_typeof(p_own) is distinct from 'object' then return jsonb_build_object('ok', false, 'err', 'bad_data'); end if;
  update public.cc_profiles set money = greatest(0, coalesce(p_money, 0)), own = p_own, updated_at = now() where name = p_name;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.cc_adm_poll(p_name text, p_token text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare r public.cc_profiles%rowtype;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into r from public.cc_profiles where name = p_name;
  return jsonb_build_object('ok', true, 'adm_seq', r.adm_seq, 'adm', r.adm);
end $$;

grant execute on function public.cc_account_status(text), public.cc_register(text, text, bigint, jsonb), public.cc_login(text, text),
  public.cc_claim(text, text), public.cc_logout(text), public.cc_set_password(text, text, text, text), public.cc_rename(text, text, text),
  public.cc_load(text, text), public.cc_save(text, text, bigint, jsonb), public.cc_adm_poll(text, text) to anon, authenticated;

-- ---------------------------------------------------------------- 관리자: 비밀번호 설정 / 확인 / 강제 로그아웃
-- (비밀번호를 "지우는" 기능은 일부러 없어요: 지우면 아무나 그 계정을 가져갈 수 있게 돼요)
create or replace function public.cc_admin_set_password(pw text, target text, new_pw text) returns int
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare n int;
begin
  perform public.cc_admin_check(pw);
  if not public.cc_pw_ok(new_pw) then raise exception 'bad password (4~64 chars)'; end if;
  update public.cc_profiles set pw_hash = extensions.crypt(new_pw, extensions.gen_salt('bf', 8)) where name = target;
  get diagnostics n = row_count;
  if n > 0 then
    delete from public.cc_sessions where name = target;
    delete from public.cc_login_fails where name = target;
  end if;
  return n;
end $$;

create or replace function public.cc_admin_pwinfo(pw text, target text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare h text; n int;
begin
  perform public.cc_admin_check(pw);
  select pw_hash into h from public.cc_profiles where name = target;
  select count(*) into n from public.cc_sessions where name = target and last_seen > now() - interval '90 days';
  return jsonb_build_object('has_pw', h is not null, 'sessions', n);
end $$;

create or replace function public.cc_admin_logout(pw text, target text) returns int
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare n int;
begin
  perform public.cc_admin_check(pw);
  delete from public.cc_sessions where name = target; get diagnostics n = row_count; return n;
end $$;

grant execute on function public.cc_admin_set_password(text, text, text), public.cc_admin_pwinfo(text, text), public.cc_admin_logout(text, text) to anon, authenticated;

-- ---------------------------------------------------------------- 기존 "이름만 받는" 함수에 토큰 검사 씌우기
-- 원래 함수는 <이름>_inner 로 바뀌고 (외부 호출 차단), 같은 이름의 새 함수가 토큰을 확인한 뒤 원래 함수를 불러요.
-- 새 함수는 마지막 인자로 p_token 을 더 받아요. 실패하면 {ok:false, err:'auth'} 를 돌려줘요.
do $mig$
declare
  t record; o oid; i_o oid; args text; callargs text; ret text; inner_name text;
begin
  for t in select * from (values
      ('cc_auction_list', 'p_seller'), ('cc_auction_cancel', 'p_seller'), ('cc_auction_buy', 'p_buyer'),
      ('cc_raid_claim', 'p_name'), ('cc_buy_global', 'p_buyer')) v(fname, namearg)
  loop
    inner_name := t.fname || '_inner';
    select p.oid into i_o from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = inner_name order by p.pronargs desc limit 1;
    if i_o is null then
      select p.oid into o from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = t.fname order by p.pronargs desc limit 1;
      if o is null then raise notice '% 함수가 없어서 건너뜀', t.fname; continue; end if;
      ret := pg_get_function_result(o);
      if ret <> 'jsonb' then raise exception '% 의 반환형이 jsonb 가 아니에요(%): 수동 확인 필요', t.fname, ret; end if;
      execute format('alter function %s rename to %I', o::regprocedure, inner_name);
      i_o := o;
    end if;
    args := pg_get_function_identity_arguments(i_o);
    select string_agg(format('%I', n), ', ' order by ord) into callargs
      from (select n, ord from pg_proc p, unnest(p.proargnames) with ordinality as u(n, ord) where p.oid = i_o) s;
    execute format($f$
      create or replace function public.%I(%s, p_token text default null) returns jsonb
      language plpgsql security definer set search_path to 'public', 'extensions' as $b$
      begin
        if not public.cc_auth_ok(%I, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
        return public.%I(%s);
      end $b$
    $f$, t.fname, args, t.namearg, inner_name, callargs);
    execute format('revoke all on function public.%I(%s) from public, anon, authenticated', inner_name, args);
    execute format('revoke all on function public.%I(%s, text) from public', t.fname, args);
    execute format('grant execute on function public.%I(%s, text) to anon, authenticated', t.fname, args);
  end loop;
end $mig$;

-- ---------------------------------------------------------------- cc_profiles 직접 접근 차단
-- 이제 돈·무기 저장은 위의 함수로만 돼요. 익명 키로 테이블을 읽거나 고칠 수 없어요(비밀번호 해시 보호 포함).
do $mig$
declare r record;
begin
  for r in select policyname from pg_policies where schemaname = 'public' and tablename = 'cc_profiles' loop
    execute format('drop policy %I on public.cc_profiles', r.policyname);
  end loop;
end $mig$;
alter table public.cc_profiles enable row level security;
revoke all on public.cc_profiles from anon, authenticated;
