-- 005_roles.sql
-- Роль script2 с минимальными правами
-- Пароль приходит psql-переменной из .env.migrate

SELECT format('CREATE ROLE script2 LOGIN PASSWORD %L', :'script2_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'script2') \gexec

GRANT SELECT, UPDATE ON live_hosts TO script2;
GRANT SELECT, INSERT ON checked_hosts TO script2;
GRANT USAGE, SELECT ON SEQUENCE checked_hosts_id_seq TO script2;
