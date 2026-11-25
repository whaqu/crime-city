-- v26: 저장 충돌 방지 (돈·무기·강화가 이유 없이 바뀌는 문제)
-- 원인: cc_save가 "무조건 덮어쓰기"라서 ① 같은 계정을 탭/기기 2곳에서 열었을 때, ② 경매·레이드·관리자가 서버에서 바꾼 직후
--       (게임이 아직 모르는 사이) 오래된 값으로 저장하면 그 변경이 지워졌어요.
-- 해결: 저장할 때 "내가 마지막으로 본 서버 버전(p_ver)"과 "내가 반영한 서버 변경 번호(p_seq)"를 같이 보내고,
--       서버가 그보다 새로우면 저장을 거절(stale) → 게임이 서버 내용을 불러와 맞춰요.
-- 여러 번 실행해도 안전해요. 실행 전에 게임(index.html)을 먼저 올려도 괜찮아요 (이 SQL이 없으면 예전 방식으로 저장).

alter table public.cc_profiles add column if not exists ver bigint not null default 0;

create or replace function public.cc_load(p_name text, p_token text) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare r public.cc_profiles%rowtype;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  select * into r from public.cc_profiles where name = p_name;
  return jsonb_build_object('ok', true, 'money', r.money, 'own', coalesce(r.own, '{}'::jsonb), 'adm_seq', r.adm_seq, 'ver', r.ver);
end $$;

drop function if exists public.cc_save(text, text, bigint, jsonb);
create or replace function public.cc_save(p_name text, p_token text, p_money bigint, p_own jsonb, p_seq bigint default null, p_ver bigint default null) returns jsonb
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare r public.cc_profiles%rowtype;
begin
  if not public.cc_auth_ok(p_name, p_token) then return jsonb_build_object('ok', false, 'err', 'auth'); end if;
  if jsonb_typeof(p_own) is distinct from 'object' then return jsonb_build_object('ok', false, 'err', 'bad_data'); end if;
  select * into r from public.cc_profiles where name = p_name for update;
  if not found then return jsonb_build_object('ok', false, 'err', 'no_profile'); end if;
  if p_seq is not null and p_seq < r.adm_seq then return jsonb_build_object('ok', false, 'err', 'stale', 'why', 'seq'); end if;
  if p_ver is not null and p_ver <> r.ver then return jsonb_build_object('ok', false, 'err', 'stale', 'why', 'ver'); end if;
  update public.cc_profiles set money = greatest(0, coalesce(p_money, 0)), own = p_own, ver = r.ver + 1, updated_at = now() where name = p_name;
  return jsonb_build_object('ok', true, 'ver', r.ver + 1);
end $$;

revoke all on function public.cc_save(text, text, bigint, jsonb, bigint, bigint) from public;
grant execute on function public.cc_load(text, text), public.cc_save(text, text, bigint, jsonb, bigint, bigint) to anon, authenticated;
