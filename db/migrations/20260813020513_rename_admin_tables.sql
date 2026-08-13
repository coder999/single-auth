-- migrate:up
RENAME TABLE admin_users TO users, admin_sessions TO sessions;

-- migrate:down
RENAME TABLE users TO admin_users, sessions TO admin_sessions;
