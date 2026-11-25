-- v25 관리자 비밀번호 보기
-- 비밀번호는 지금까지 복원이 안 되는 암호화 값(pw_hash)으로만 저장됐어요. 이 파일을 적용하면
-- 비밀번호를 "복호화할 수 있는 형태"로도 따로 보관해서 관리자 페이지에서 볼 수 있어요.
--   · 이미 걸려 있는 비밀번호는 원문을 알 수 없어요 → 그 유저가 비밀번호로 다시 로그인(또는 변경)하는 순간부터 보여요
--   · 보관 값은 서버 안의 비밀 키(cc_secret)로 암호화돼 있고, 공개 키로는 읽을 수 없어요. 단, 관리자 비밀번호를 아는 사람은 볼 수 있어요
--   · 보기 싫어지면 맨 아래 '끄기' 주석을 실행하면 보관된 값이 전부 지워져요
-- v24_auth.sql 이 먼저 적용돼 있어야 해요. 여러 번 실행해도 안전해요.

create table if not exists public.cc_secret (id int primary key default 1 check (id = 1), k text not null);
alter table public.cc_secret enable row level security;
revoke all on public.cc_secret from anon, authenticated;
insert into public.cc_secret (id, k) values (1, encode(extensions.gen_random_bytes(32), 'hex')) on conflict (id) do nothing;

alter table public.cc_profiles add column if not exists pw_enc bytea;

create or replace function public.cc_pw_store(p_name text, p_pw text) returns void
language plpgsql security definer set search_path to 'public', 'extensions' as $$
begin
  if p_pw is null or p_pw = '' then return; end if;
  update public.cc_profiles set pw_enc = extensions.pgp_sym_encrypt(p_pw, (select k from public.cc_secret where id = 1)) where name = p_name;
end $$;
revoke all on function public.cc_pw_store(text, text) from public, anon, authenticated;

-- 관리자: 이 계정의 현재 비밀번호 (모르면 pw 가 null)
create or replace function public.cc_admin_pwview(pw text, target text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare h text; e bytea; v text;
begin
  perform public.cc_admin_check(pw);
  select pw_hash, pw_enc into h, e from public.cc_profiles where name = target;
  if e is not null then v := extensions.pgp_sym_decrypt(e, (select k from public.cc_secret where id = 1)); end if;
  return jsonb_build_object('has_pw', h is not null, 'pw', v);
end $$;
grant execute on function public.cc_admin_pwview(text, text) to anon, authenticated;

-- ---------------------------------------------------------------- v24 함수에 '보관' 한 줄씩만 추가
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
    perform public.cc_pw_store(p_name, p_pw);
    delete from public.cc_login_fails where name = p_name;
    return jsonb_build_object('ok', true);
  end if;
  insert into public.cc_login_fails (name, fails, last_at) values (p_name, 1, now())
    on conflict (name) do update set fails = case when public.cc_login_fails.last_at < now() - interval '1 hour' then 1 else public.cc_login_fails.fails + 1 end, last_at = now()
    returning fails into n;
  if n >= 5 then update public.cc_login_fails set locked_until = now() + case when n >= 10 then interval '5 minutes' else interval '1 minute' end where name = p_name; end if;
  return jsonb_build_object('ok', false, 'err', 'bad_pw', 'left', greatest(0, 5 - n));
end $$;

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
  perform public.cc_pw_store(p_name, p_pw);
  t := public.cc_new_session(p_name);
  return jsonb_build_object('ok', true, 'token', t);
end $$;

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
  perform public.cc_pw_store(p_name, p_pw);
  return jsonb_build_object('ok', true, 'token', public.cc_new_session(p_name));
end $$;

create or replace function public.cc_set_password(p_name text, p_token text, p_old text, p_new text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare v jsonb;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if not public.cc_pw_ok(p_new) then return jsonb_build_object('ok', false, 'err', 'bad_pw_fmt'); end if;
  v := public.cc_pw_verify(p_name, p_old);
  if not (v ->> 'ok')::boolean then return v; end if;
  update public.cc_profiles set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 8)) where name = p_name;
  perform public.cc_pw_store(p_name, p_new);
  delete from public.cc_sessions where name = p_name and token_hash <> encode(extensions.digest(p_token, 'sha256'), 'hex');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.cc_admin_set_password(pw text, target text, new_pw text) returns int
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare n int;
begin
  perform public.cc_admin_check(pw);
  if not public.cc_pw_ok(new_pw) then raise exception 'bad password (4~64 chars)'; end if;
  update public.cc_profiles set pw_hash = extensions.crypt(new_pw, extensions.gen_salt('bf', 8)) where name = target;
  get diagnostics n = row_count;
  if n > 0 then
    perform public.cc_pw_store(target, new_pw);
    delete from public.cc_sessions where name = target;
    delete from public.cc_login_fails where name = target;
  end if;
  return n;
end $$;

-- ---------------------------------------------------------------- (끄고 싶을 때) 보관된 비밀번호를 전부 지우려면 아래 한 줄을 따로 실행하세요
-- update public.cc_profiles set pw_enc = null;
