-- Whether anyone reaching the console may create a local account for themselves. One row, which
-- the check keeps the only one, so the switch has nowhere to be read from but here; closed until
-- a superuser opens it. A sign-up reads the row `for share` and the switch takes it `for update`,
-- so a sign-up in flight when sign-up closes finishes first, and none starts after.
create table console_settings (
    only_row boolean primary key default true check (only_row),
    sign_up_open boolean not null default false
);
insert into console_settings default values;

-- What someone wrote when they signed up, for whoever decides what to grant them. Plain text, at
-- most 500 characters, which the form enforces; null when they wrote nothing.
alter table users add column signup_note text;
