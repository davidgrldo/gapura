-- Whether anyone reaching the console may create a local account for themselves. One row, which
-- the check keeps the only one, so the switch has nowhere to be read from but here; closed until
-- a superuser opens it. A sign-up and a change of the switch both take the row `for update`, so a
-- sign-up in flight when sign-up closes finishes first, none starts after, and sign-ups take
-- turns, which keeps the count of waiting accounts each one reads exact.
create table console_settings (
    only_row boolean primary key default true check (only_row),
    sign_up_open boolean not null default false
);
insert into console_settings default values;

-- What someone wrote when they signed up, for whoever decides what to grant them: plain text,
-- null when they wrote nothing. And when they signed up, which only sign-up sets: the accounts
-- waiting for access that sign-up made are counted by it, and sign-up refuses past a ceiling.
alter table users
    add column signup_note text constraint users_signup_note_length
        check (char_length(signup_note) <= 500),
    add column signed_up_at timestamptz;
