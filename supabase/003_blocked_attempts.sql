-- Count blocked repeat tries per poll (shown only to the admin).
-- Applied to the live project as migration "count_blocked_attempts".
alter table public.polls add column if not exists blocked_attempts int not null default 0;
-- get_poll_open: an already-voted phone opening the link while voting is open = +1 blocked try.
-- cast_vote_open: now returns json {ok:false} on a repeat (instead of raising) so the +1 isn't rolled back.
-- get_results: adds 'blocked' (admin only).
-- Full function bodies: see the live migration; same code as in 002 with those changes.
