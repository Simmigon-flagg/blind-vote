# Blind Vote

Single-question anonymous poll. Static page (GitHub Pages) + Supabase.

- Creator gets one **admin link** and one **voting link** to share with everyone (one vote per phone).
- Each voter link works once, enforced server-side (refresh, incognito, other device: no extra vote).
- Ballots store only the choice: no token, no voter ID, no timestamp.
- Results are visible to the admin live, and to everyone after the admin closes voting.

## Setup (5 min)
1. Create a Supabase project (free tier is fine).
2. SQL Editor → paste `supabase/schema.sql` → Run.
3. Project Settings → API → copy the Project URL and publishable (anon) key into `config.js`.
4. Commit. GitHub Pages serves the app.

## Why not browser storage?
localStorage/IndexedDB live on one device in one browser. Other voters' browsers can't read them, and clearing storage or opening incognito resets them. A shared server is required to count votes and enforce one-per-person.

## Known limits
- One vote per **link**, not per human. Send each person exactly one link.
- Anyone with the page can create polls (capped at 500 voters / 20 options).
