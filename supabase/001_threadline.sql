-- Threadline shared backend, Phase 1.
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Every table has row level security: a signed-in person only sees projects they belong to.

create extension if not exists pgcrypto;

-- Projects: one per chat / job
create table if not exists public.projects (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(name) between 1 and 80),
  created_by  uuid not null default auth.uid() references auth.users(id) on delete set null,
  created_at  timestamptz not null default now()
);

-- Who belongs to each project
create table if not exists public.project_members (
  project_id  uuid not null references public.projects(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  role        text not null default 'member' check (role in ('owner','member')),
  email       text,
  joined_at   timestamptz not null default now(),
  primary key (project_id, user_id)
);

-- Pending invites by email; turned into memberships when that person signs in
create table if not exists public.project_invites (
  id          uuid primary key default gen_random_uuid(),
  project_id  uuid not null references public.projects(id) on delete cascade,
  email       text not null check (email = lower(email)),
  invited_by  uuid default auth.uid() references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  unique (project_id, email)
);

-- Chat messages. seq is the message's position in the project (the app's message id).
-- wa_message_id is filled by live WhatsApp sync in Phase 2 and stops duplicates.
create table if not exists public.messages (
  id            bigint generated always as identity primary key,
  project_id    uuid not null references public.projects(id) on delete cascade,
  seq           integer not null,
  sent_at       timestamptz not null,
  author        text not null,
  body          text not null default '',
  has_media     boolean not null default false,
  source        text not null default 'import' check (source in ('import','whatsapp')),
  wa_message_id text unique,
  created_at    timestamptz not null default now(),
  unique (project_id, seq)
);
create index if not exists messages_project_seq on public.messages (project_id, seq);

-- Shared state for items found in the chat: done ticks and owner overrides
create table if not exists public.item_state (
  project_id  uuid not null references public.projects(id) on delete cascade,
  seq         integer not null,
  done        boolean not null default false,
  owner       text,
  updated_by  uuid default auth.uid() references auth.users(id) on delete set null,
  updated_at  timestamptz not null default now(),
  primary key (project_id, seq)
);

-- Helpers (security definer so policies can check membership without recursion)
create or replace function public.is_member(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from project_members where project_id = p and user_id = auth.uid());
$$;

create or replace function public.is_owner(p uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from project_members where project_id = p and user_id = auth.uid() and role = 'owner');
$$;

-- Whoever creates a project becomes its owner
create or replace function public.add_project_owner() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into project_members (project_id, user_id, role, email)
  values (new.id, new.created_by, 'owner', lower(auth.jwt() ->> 'email'));
  return new;
end $$;
drop trigger if exists projects_add_owner on public.projects;
create trigger projects_add_owner after insert on public.projects
  for each row execute function public.add_project_owner();

-- Called by the app after sign-in: accept every invite sent to this person's email
create or replace function public.accept_invites() returns integer
language plpgsql security definer set search_path = public as $$
declare my_email text := lower(auth.jwt() ->> 'email'); n integer;
begin
  if auth.uid() is null or my_email is null then return 0; end if;
  insert into project_members (project_id, user_id, role, email)
    select project_id, auth.uid(), 'member', my_email from project_invites where email = my_email
    on conflict do nothing;
  get diagnostics n = row_count;
  delete from project_invites where email = my_email;
  return n;
end $$;

-- Keep updated_at / updated_by honest
create or replace function public.touch_item_state() returns trigger
language plpgsql as $$
begin new.updated_at := now(); new.updated_by := auth.uid(); return new; end $$;
drop trigger if exists item_state_touch on public.item_state;
create trigger item_state_touch before insert or update on public.item_state
  for each row execute function public.touch_item_state();

-- Row level security
alter table public.projects        enable row level security;
alter table public.project_members enable row level security;
alter table public.project_invites enable row level security;
alter table public.messages        enable row level security;
alter table public.item_state      enable row level security;

drop policy if exists "members read projects" on public.projects;
create policy "members read projects" on public.projects for select using (public.is_member(id));
drop policy if exists "signed-in people create projects" on public.projects;
create policy "signed-in people create projects" on public.projects for insert with check (auth.uid() is not null and created_by = auth.uid());
drop policy if exists "owners rename projects" on public.projects;
create policy "owners rename projects" on public.projects for update using (public.is_owner(id));
drop policy if exists "owners delete projects" on public.projects;
create policy "owners delete projects" on public.projects for delete using (public.is_owner(id));

drop policy if exists "members see members" on public.project_members;
create policy "members see members" on public.project_members for select using (public.is_member(project_id));
drop policy if exists "owners remove members, people leave" on public.project_members;
create policy "owners remove members, people leave" on public.project_members for delete using (public.is_owner(project_id) or user_id = auth.uid());

drop policy if exists "members and invitees see invites" on public.project_invites;
create policy "members and invitees see invites" on public.project_invites for select using (public.is_member(project_id) or email = lower(auth.jwt() ->> 'email'));
drop policy if exists "members invite" on public.project_invites;
create policy "members invite" on public.project_invites for insert with check (public.is_member(project_id));
drop policy if exists "members cancel invites" on public.project_invites;
create policy "members cancel invites" on public.project_invites for delete using (public.is_member(project_id));

drop policy if exists "members read messages" on public.messages;
create policy "members read messages" on public.messages for select using (public.is_member(project_id));
drop policy if exists "members add messages" on public.messages;
create policy "members add messages" on public.messages for insert with check (public.is_member(project_id));
drop policy if exists "owners delete messages" on public.messages;
create policy "owners delete messages" on public.messages for delete using (public.is_owner(project_id));

drop policy if exists "members read item state" on public.item_state;
create policy "members read item state" on public.item_state for select using (public.is_member(project_id));
drop policy if exists "members write item state" on public.item_state;
create policy "members write item state" on public.item_state for insert with check (public.is_member(project_id));
drop policy if exists "members update item state" on public.item_state;
create policy "members update item state" on public.item_state for update using (public.is_member(project_id));

grant execute on function public.accept_invites() to authenticated;

-- Live updates: ticks, owners and new messages reach every open screen
do $$ begin
  begin alter publication supabase_realtime add table public.item_state; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.messages;   exception when duplicate_object then null; end;
end $$;
