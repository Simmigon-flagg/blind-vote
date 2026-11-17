-- Blind Vote schema. Tables are fully locked by RLS; all access goes through
-- SECURITY DEFINER functions so voters can never read other votes or admin tokens.

create extension if not exists pgcrypto;

create table public.polls (
  id          uuid primary key default gen_random_uuid(),
  question    text not null check (char_length(question) between 1 and 500),
  options     text[] not null check (array_length(options, 1) between 2 and 10),
  admin_token uuid not null default gen_random_uuid(),
  closed      boolean not null default false,
  created_at  timestamptz not null default now()
);

create table public.votes (
  id          bigint generated always as identity primary key,
  poll_id     uuid not null references public.polls(id) on delete cascade,
  choice      int  not null,
  voter_token uuid not null,
  created_at  timestamptz not null default now(),
  unique (poll_id, voter_token)
);

alter table public.polls enable row level security;
alter table public.votes enable row level security;
-- No policies on purpose: anon/authenticated cannot touch tables directly.

-- Create a poll. Returns the public id and the secret admin token.
create or replace function public.create_poll(p_question text, p_options text[])
returns table (id uuid, admin_token uuid)
language sql security definer set search_path = public as $$
  insert into polls (question, options)
  values (trim(p_question), p_options)
  returning polls.id, polls.admin_token;
$$;

-- Public poll info for voters. No counts: the vote is blind.
create or replace function public.get_poll(p_id uuid)
returns table (question text, options text[], closed boolean)
language sql stable security definer set search_path = public as $$
  select question, options, closed from polls where polls.id = p_id;
$$;

-- Cast one vote per voter token. Returns false if already voted.
create or replace function public.cast_vote(p_id uuid, p_choice int, p_voter uuid)
returns boolean
language plpgsql security definer set search_path = public as $$
declare v_opts text[]; v_closed boolean;
begin
  select options, closed into v_opts, v_closed from polls where id = p_id;
  if v_opts is null then raise exception 'Poll not found'; end if;
  if v_closed then raise exception 'Voting is closed'; end if;
  if p_choice < 0 or p_choice >= array_length(v_opts, 1) then
    raise exception 'Invalid choice';
  end if;
  insert into votes (poll_id, choice, voter_token) values (p_id, p_choice, p_voter)
  on conflict (poll_id, voter_token) do nothing;
  return found;
end $$;

-- Results: admin token required.
create or replace function public.get_results(p_id uuid, p_admin uuid)
returns table (choice int, label text, votes bigint)
language plpgsql stable security definer set search_path = public as $$
declare v_opts text[];
begin
  select options into v_opts from polls where id = p_id and admin_token = p_admin;
  if v_opts is null then raise exception 'Not authorized'; end if;
  return query
    select (i - 1)::int, v_opts[i], count(v.id)
    from generate_subscripts(v_opts, 1) as i
    left join votes v on v.poll_id = p_id and v.choice = i - 1
    group by i order by i;
end $$;

-- Close or reopen voting: admin token required.
create or replace function public.set_closed(p_id uuid, p_admin uuid, p_closed boolean)
returns boolean
language sql security definer set search_path = public as $$
  update polls set closed = p_closed where id = p_id and admin_token = p_admin
  returning true;
$$;

revoke all on function public.create_poll, public.get_poll, public.cast_vote,
  public.get_results, public.set_closed from public;
grant execute on function public.create_poll, public.get_poll, public.cast_vote,
  public.get_results, public.set_closed to anon, authenticated;
