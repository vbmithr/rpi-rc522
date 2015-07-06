create table if not exists accesses (
       uuid blob primary key,
       descr text,
       cond blob
);

create table if not exists keys (
       uid integer,
       access blob,
       privkey blob,
       secret blob
);
