DROP INDEX IF EXISTS idx_refresh_token_user_id;
DROP INDEX IF EXISTS idx_refresh_token_jwt_id;

DROP TABLE IF EXISTS refresh_tokens;

DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "uuid-ossp";