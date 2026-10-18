-- 007_panel_grants.sql
-- Права панели админа на checked_hosts:
-- UPDATE — смена panel_status (active/complete/hidden) по всем попыткам хоста,
-- DELETE — стирание результатов active-хостов при отправке на перепроверку
-- (эндпоинт /api/active/clear: DELETE + возврат live_hosts в 'new')

GRANT UPDATE, DELETE ON checked_hosts TO script2;
