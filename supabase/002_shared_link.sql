-- Shared-link polls: ONE voting link for everyone, one vote per browser/device.
-- The browser keeps a random device id; the server stores only its hash, in a table that has
-- NO link to the ballots table, so votes still can't be traced to a voter.

create table if not exists public.voter_devices (
  poll_id      uuid not null references public.polls(id) on delete cascade,
  device_hash  text not null,
  primary key (poll_id, device_hash)
);
alter table public.voter_devices enable row level security;
-- No policies = no direct table access. RPCs only.

-- Create a shared-link poll. Returns poll id + admin key (shown once, stored hashed).
create or replace function public.create_poll_open(p_question text, p_options text[])
returns json language plpgsql security definer set search_path = '' as $$
declare v_id uuid; v_admin text;
begin
  if exists (select 1 from unnest(p_options) o where char_length(trim(o)) = 0 or char_length(o) > 200) then
    raise exception 'Options must be 1-200 characters';
  end if;
  v_admin := public._tok();
  insert into public.polls(question, options, admin_hash)
    values (trim(p_question), p_options, public._h(v_admin)) returning id into v_id;
  return json_build_object('poll_id', v_id, 'admin_key', v_admin);
end $$;

-- Poll info + whether this device has already voted.
create or replace function public.get_poll_open(p_poll uuid, p_device text)
returns json language plpgsql security definer set search_path = '' as $$
declare r public.polls;
begin
  select * into r from public.polls where id = p_poll;
  if not found then raise exception 'Poll not found'; end if;
  return json_build_object('question', r.question, 'options', r.options, 'closed', r.closed,
    'voted', exists (select 1 from public.voter_devices where poll_id = p_poll and device_hash = public._h(p_device)));
end $$;

-- Cast a vote. Atomic: the primary key lets each device insert exactly once, even under concurrent requests.
create or replace function public.cast_vote_open(p_poll uuid, p_device text, p_choice int)
returns void language plpgsql security definer set search_path = '' as $$
declare r public.polls; n int;
begin
  if p_device is null or char_length(p_device) < 16 then raise exception 'Invalid device'; end if;
  select * into r from public.polls where id = p_poll;
  if not found then raise exception 'Poll not found'; end if;
  if r.closed then raise exception 'Voting is closed'; end if;
  -- polls made with one-time voter links can only be voted on through those links
  if exists (select 1 from public.voter_tokens where poll_id = p_poll) then raise exception 'This poll needs your personal voting link'; end if;
  if p_choice < 0 or p_choice >= array_length(r.options, 1) then raise exception 'Invalid choice'; end if;
  insert into public.voter_devices(poll_id, device_hash) values (p_poll, public._h(p_device))
    on conflict do nothing;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'You already voted on this device'; end if;
  insert into public.ballots(poll_id, choice) values (p_poll, p_choice);
end $$;

-- Results now count ballots directly, so they work for both link styles. total = 0 for shared-link polls.
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
    'voted',  (select count(*) from public.ballots where poll_id = p_poll),
    'total',  (select count(*) from public.voter_tokens where poll_id = p_poll));
end $$;

revoke all on function public.create_poll_open(text, text[]), public.get_poll_open(uuid, text),
  public.cast_vote_open(uuid, text, int) from public;
grant execute on function public.create_poll_open(text, text[]), public.get_poll_open(uuid, text),
  public.cast_vote_open(uuid, text, int), public.get_results(uuid, text) to anon, authenticated;
