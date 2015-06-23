create table if not exists accesses (
       id integer primary key,
       descr text,
       cond blob
);

create table if not exists keys (
       uid integer,
       access_id integer,
       privkey blob,
       secret blob
);
