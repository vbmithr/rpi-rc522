create table accesses (
       id int primary key,
       descr varchar(100),
       condition varchar(100)
       );

create table keys (
       uid varchar(12) primary key,
       privkey varchar(128),
       secret varchar(128)
       );
