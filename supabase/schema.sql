-- Blind Vote schema. Paste into Supabase SQL Editor and run once.
-- Design:
--   * Every voter gets a one-time token (in their link). Server marks it used atomically.
--   * Ballots are stored with NO token reference and NO timestamp -> votes can't be traced to a voter.
--   * Tables are locked by RLS; the browser can only call the RPC functions below.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.polls (
  id          uuid primary key default gen_random_uuid(),
  question    text not null check (char_length(question) between 1 and 500),
  options     text[] not null check (array_length(options, 1) between 2 and 20),
  admin_hash  text not null,
  closed      boolean not null default false,
  created_at  timestamptz not null default now()
);

create table if not exists public.voter_tokens (
  poll_id     uuid not null references public.polls(id) on delete cascade,
  token_hash  text not null,
  used        boolean not null default false,
  primary key (poll_id, token_hash)
);

-- Intentionally no token, no voter id, no created_at.
create table if not exists public.ballots (
  id       bigint generated always as identity primary key,
  poll_id  uuid not null references public.polls(id) on delete cascade,
  choice   int  not null
);

alter table public.polls        enable row level security;
alter table public.voter_tokens enable row level security;
alter table public.ballots      enable row level security;
-- No policies = no direct table access for anon/authenticated. RPCs only.

create or replace function public._h(t text) returns text
language sql immutable set search_path = '' as $$
  select encode(extensions.digest(t, 'sha256'), 'hex')
$$;

create or replace function public._tok() returns text
language sql volatile set search_path = '' as $$
  select translate(encode(extensions.gen_random_bytes(16), 'base64'), '+/=', '-_')
$$;

-- Create a poll. Returns poll id, admin key, and one token per voter (shown once, never stored in plain text).
create or replace function public.create_poll(p_question text, p_options text[], p_voters int)
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_id uuid; v_admin text; v_tokens text[] := '{}'; v_t text; i int;
begin
  if p_voters is null or p_voters < 1 or p_voters > 500 then
    raise exception 'Voters must be between 1 and 500';
  end if;
  if exists (select 1 from unnest(p_options) o where char_length(trim(o)) = 0 or char_length(o) > 200) then
    raise exception 'Options must be 1-200 characters';
  end if;
  v_admin := public._tok();
  insert into public.polls(question, options, admin_hash)
    values (trim(p_question), p_options, public._h(v_admin)) returning id into v_id;
  for i in 1..p_voters loop
    v_t := public._tok();
    insert into public.voter_tokens(poll_id, token_hash) values (v_id, public._h(v_t));
    v_tokens := v_tokens || v_t;
  end loop;
  return json_build_object('poll_id', v_id, 'admin_key', v_admin, 'tokens', v_tokens);
end $$;

-- Public poll info + whether this token has already voted.
create or replace function public.get_poll(p_poll uuid, p_token text default null)
returns json language plpgsql security definer set search_path = '' as $$
declare r public.polls; v_used boolean;
begin
  select * into r from public.polls where id = p_poll;
  if not found then raise exception 'Poll not found'; end if;
  if p_token is not null then
    select used into v_used from public.voter_tokens
      where poll_id = p_poll and token_hash = public._h(p_token);
  end if;
  return json_build_object('question', r.question, 'options', r.options, 'closed', r.closed,
                           'token_valid', v_used is not null, 'token_used', coalesce(v_used, false));
end $$;

-- Cast a vote. Atomic: token flips used=false -> true exactly once, even under concurrent requests.
create or replace function public.cast_vote(p_poll uuid, p_token text, p_choice int)
returns void language plpgsql security definer set search_path = '' as $$
declare r public.polls; n int;
begin
  select * into r from public.polls where id = p_poll;
  if not found then raise exception 'Poll not found'; end if;
  if r.closed then raise exception 'Voting is closed'; end if;
  if p_choice < 0 or p_choice >= array_length(r.options, 1) then raise exception 'Invalid choice'; end if;
  update public.voter_tokens set used = true
    where poll_id = p_poll and token_hash = public._h(p_token) and used = false;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'This link has already been used or is invalid'; end if;
  insert into public.ballots(poll_id, choice) values (p_poll, p_choice);
end $$;

-- Results: admin anytime; everyone once closed.
create or replace function public.get_results(p_poll uuid, p_admin text default null)
returns json language plpgsql security definer set search_path = '' as $$
declare r public.polls; is_admin boolean;
begin
  select * into r from public.polls where id = p_poll;
  if not found then raise exception 'Poll not found'; end if;
  is_admin := p_admin is not null and public._h(p_admin) = r.admin_hash;
  if not is_admin and not r.closed then raise exception 'Results are hidden until voting closes'; end if;
  return json_build_object(
    'question', r.question, 'options', r.options, 'closed', r.closed, 'is_admin', is_admin,
    'counts', (select coalesce(json_agg(c order by i), '[]'::json) from (
                 select i, (select count(*) from public.ballots b where b.poll_id = p_poll and b.choice = i - 1) c
                 from generate_series(1, array_length(r.options, 1)) i) s),
    'voted',  (select count(*) from public.voter_tokens where poll_id = p_poll and used),
    'total',  (select count(*) from public.voter_tokens where poll_id = p_poll));
end $$;

create or replace function public.set_closed(p_poll uuid, p_admin text, p_closed boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.polls set closed = p_closed where id = p_poll and admin_hash = public._h(p_admin);
  if not found then raise exception 'Invalid admin key'; end if;
end $$;

revoke all on function public._h(text), public._tok() from public, anon, authenticated;
revoke all on function public.create_poll(text, text[], int), public.get_poll(uuid, text),
  public.cast_vote(uuid, text, int), public.get_results(uuid, text), public.set_closed(uuid, text, boolean)
  from public;
grant execute on function public.create_poll(text, text[], int), public.get_poll(uuid, text),
  public.cast_vote(uuid, text, int), public.get_results(uuid, text), public.set_closed(uuid, text, boolean)
  to anon, authenticated;
