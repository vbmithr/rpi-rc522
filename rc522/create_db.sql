create table if not exists accesses (
       id integer primary key,
       descr text,
       cond blob
);

create table if not exists keys (
       uid integer primary key,
       accessid integer,
       privkey blob,
       secret blob
);
