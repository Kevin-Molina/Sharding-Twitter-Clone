drop table if exists user;
create table user (
  user_id GUID PRIMARY KEY,
  username text not null,
  email text not null,
  pw_hash text not null
);

drop table if exists follower;
create table follower (
  who_id GUID,
  whom_id GUID
);

drop table if exists message;
create table message (
  message_id GUID PRIMARY KEY,
  author_id GUID not null,
  text text not null,
  pub_date integer
);
