-- LOC STAR / SHOP MM - initial Supabase schema
-- Chạy phần này trong Supabase SQL Editor.
-- KHÔNG đưa mật khẩu ngân hàng, OTP hoặc PIN vào đây.

create extension if not exists pgcrypto;

create table if not exists public.app_users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  full_name text,
  balance numeric(18,2) not null default 0 check (balance >= 0),
  deposit_code text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists public.bank_transactions (
  id bigint generated always as identity primary key,
  transaction_id text not null unique,
  gateway text,
  account_number text,
  transaction_date timestamptz,
  amount numeric(18,2) not null check (amount > 0),
  content text not null default '',
  reference_code text,
  raw_payload jsonb,
  status text not null default 'received',
  matched_user_id uuid references public.app_users(id),
  processed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.ledger (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.app_users(id),
  type text not null check (type in ('deposit','order','refund','adjustment')),
  amount numeric(18,2) not null,
  balance_after numeric(18,2) not null,
  reference_id text,
  note text,
  created_at timestamptz not null default now()
);

create index if not exists idx_bank_transactions_content
  on public.bank_transactions (content);

create index if not exists idx_ledger_user_created
  on public.ledger (user_id, created_at desc);
