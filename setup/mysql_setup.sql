create database IDSDeathBlossom;
grant INSERT,SELECT,UPDATE,DELETE on IDSDeathBlossom.* to someuser@localhost identified by 'somepass';
use IDSDeathBlossom;
create table rulestats (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, primary key (id), host text, timestamp text, runid text, file text, alertfile text, engine text, rank integer , sid integer, gid integer, rev integer , checks integer, matches integer, alerts integer, microsecs BIGINT UNSIGNED, avgtcheck float, avgtmatch float, avgtnomatch float);

create table filestats (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, primary key (id), host text, timestamp text, runid text, cmd text, file text, engine text, runtime text, ualerts text, alertfile text, alertcnt integer, exitcode integer);
create table alerts (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, primary key (id), host text, timestamp text, runid text, file text, engine text, alertfile text, sid BIGINT UNSIGNED NOT NULL, gid BIGINT UNSIGNED NOT NULL,rev BIGINT UNSIGNED NOT NULL, msg text, class text, prio text, proto text, src INT UNSIGNED, dst INT UNSIGNED, sport int, dport int);
create table report (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, primary key (id), timestamp text, status text, engine text, path text, relpath text, errors integer, warnings integer, time integer, commented integer, reportgroup text);
