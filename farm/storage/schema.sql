CREATE TABLE IF NOT EXISTS schema_migrations (
 version INT PRIMARY KEY, applied_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS accounts (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 account_key CHAR(64) NOT NULL UNIQUE, label VARCHAR(120) NOT NULL,
 user_id VARCHAR(40) NULL, region VARCHAR(8) NOT NULL DEFAULT 'BR',
 identity_status VARCHAR(32) NOT NULL DEFAULT 'unverified',
 active_session_id BIGINT UNSIGNED NULL, paused BOOLEAN NOT NULL DEFAULT FALSE,
 verified_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS account_sessions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, account_id BIGINT UNSIGNED NOT NULL,
 source_key CHAR(64) NOT NULL UNIQUE, source_label VARCHAR(200) NOT NULL,
 installation_key CHAR(64) NOT NULL, encryption_key_id CHAR(16) NOT NULL,
 credential_blob LONGBLOB NOT NULL, material_status VARCHAR(40) NOT NULL,
 incognia_mode VARCHAR(20) NOT NULL, collection_mode VARCHAR(20) NOT NULL,
 endpoint_names JSON NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 FOREIGN KEY (account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS capabilities (
 session_id BIGINT UNSIGNED NOT NULL, endpoint VARCHAR(40) NOT NULL,
 state VARCHAR(32) NOT NULL DEFAULT 'unknown', observed_at DATETIME(6) NULL,
 http_status INT NULL, business_code VARCHAR(64) NULL, evidence_source VARCHAR(200) NULL,
 not_before DATETIME(6) NULL, PRIMARY KEY(session_id,endpoint),
 FOREIGN KEY (session_id) REFERENCES account_sessions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS budget_policies (
 account_id BIGINT UNSIGNED NOT NULL, endpoint VARCHAR(40) NOT NULL,
 work_limit INT UNSIGNED NOT NULL, hard_limit INT UNSIGNED NOT NULL,
 timezone VARCHAR(64) NOT NULL DEFAULT 'America/Sao_Paulo',
 PRIMARY KEY(account_id,endpoint), FOREIGN KEY(account_id) REFERENCES accounts(id),
 CHECK (work_limit <= hard_limit)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS daily_usage (
 account_id BIGINT UNSIGNED NOT NULL, business_date DATE NOT NULL, endpoint VARCHAR(40) NOT NULL,
 used_count INT UNSIGNED NOT NULL DEFAULT 0, reserved_count INT UNSIGNED NOT NULL DEFAULT 0,
 PRIMARY KEY(account_id,business_date,endpoint), FOREIGN KEY(account_id) REFERENCES accounts(id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS collection_runs (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, run_key CHAR(64) NOT NULL UNIQUE,
 label VARCHAR(160) NOT NULL, source_kind VARCHAR(24) NOT NULL,
 status VARCHAR(24) NOT NULL DEFAULT 'ready', settings JSON NOT NULL, created_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS shop_jobs (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, run_id BIGINT UNSIGNED NOT NULL,
 shop_id VARCHAR(40) NOT NULL, latitude VARCHAR(32) NOT NULL, longitude VARCHAR(32) NOT NULL,
 city_id VARCHAR(40) NOT NULL, shop_name VARCHAR(255) NULL, context_key CHAR(64) NOT NULL,
 UNIQUE(run_id,shop_id,context_key), FOREIGN KEY(run_id) REFERENCES collection_runs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS tasks (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, task_key CHAR(64) NOT NULL UNIQUE,
 shop_job_id BIGINT UNSIGNED NOT NULL, endpoint VARCHAR(40) NOT NULL, target_id VARCHAR(80) NOT NULL DEFAULT '',
 payload JSON NOT NULL, state VARCHAR(32) NOT NULL DEFAULT 'pending',
 priority INT NOT NULL DEFAULT 0, attempts INT UNSIGNED NOT NULL DEFAULT 0,
 max_attempts INT UNSIGNED NOT NULL DEFAULT 3, not_before DATETIME(6) NULL,
 lease_owner CHAR(36) NULL, lease_until DATETIME(6) NULL,
 last_reason VARCHAR(100) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX queue_claim(state,endpoint,not_before,priority), FOREIGN KEY(shop_job_id) REFERENCES shop_jobs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS request_attempts (
 id CHAR(64) PRIMARY KEY, account_id BIGINT UNSIGNED NOT NULL, session_id BIGINT UNSIGNED NOT NULL,
 task_id BIGINT UNSIGNED NULL, endpoint VARCHAR(40) NOT NULL, origin VARCHAR(32) NOT NULL,
 started_at DATETIME(6) NOT NULL, finished_at DATETIME(6) NULL, business_date DATE NOT NULL,
 state VARCHAR(24) NOT NULL, counts_budget BOOLEAN NOT NULL DEFAULT TRUE,
 http_status INT NULL, business_code VARCHAR(64) NULL, outcome VARCHAR(40) NOT NULL,
 valid_data BOOLEAN NOT NULL DEFAULT FALSE, error_type VARCHAR(120) NULL,
 shop_id VARCHAR(40) NULL, product_id VARCHAR(40) NULL, source_ref VARCHAR(240) NULL,
 signer_mode VARCHAR(32) NULL, incognia_mode VARCHAR(20) NULL,
 INDEX daily_stats(account_id,business_date,endpoint), INDEX task_attempts(task_id),
 FOREIGN KEY(account_id) REFERENCES accounts(id), FOREIGN KEY(session_id) REFERENCES account_sessions(id),
 FOREIGN KEY(task_id) REFERENCES tasks(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS task_results (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, result_key CHAR(64) NOT NULL UNIQUE,
 shop_job_id BIGINT UNSIGNED NOT NULL, task_id BIGINT UNSIGNED NULL,
 account_id BIGINT UNSIGNED NULL, endpoint VARCHAR(40) NOT NULL, target_id VARCHAR(80) NOT NULL DEFAULT '',
 observed_at DATETIME(6) NOT NULL, valid_data BOOLEAN NOT NULL,
 response_blob LONGBLOB NOT NULL, response_sha256 CHAR(64) NOT NULL,
 INDEX export_results(shop_job_id,endpoint), FOREIGN KEY(shop_job_id) REFERENCES shop_jobs(id),
 FOREIGN KEY(task_id) REFERENCES tasks(id), FOREIGN KEY(account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS experiment_members (
 account_id BIGINT UNSIGNED NOT NULL, experiment_name VARCHAR(100) NOT NULL,
 endpoint VARCHAR(40) NOT NULL, target_attempts INT UNSIGNED NOT NULL,
 rest_hours INT UNSIGNED NOT NULL DEFAULT 24, state VARCHAR(32) NOT NULL DEFAULT 'ready',
 rest_until DATETIME(6) NULL, settings JSON NOT NULL,
 PRIMARY KEY(account_id,experiment_name,endpoint), FOREIGN KEY(account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE OR REPLACE VIEW daily_account_requests AS
SELECT a.account_id, ac.label, ac.user_id, a.business_date, a.endpoint, a.origin,
 SUM(a.counts_budget AND a.state IN ('sent','done','uncertain')) AS request_count,
 SUM(a.state='reserved') AS reserved_count,
 SUM(a.http_status=200) AS http_200_count, SUM(a.valid_data) AS valid_data_count,
 SUM(a.http_status=403) AS http_403_count, SUM(a.http_status=429) AS http_429_count,
 SUM(a.outcome='business_error' OR a.outcome='store_closed') AS business_error_count,
 SUM(a.outcome='transport_error') AS transport_error_count,
 SUM(a.state='local_error') AS local_error_count
FROM request_attempts a JOIN accounts ac ON ac.id=a.account_id
GROUP BY a.account_id,ac.label,ac.user_id,a.business_date,a.endpoint,a.origin;
CREATE OR REPLACE VIEW account_status AS
SELECT a.id,a.label,a.user_id,a.region,a.identity_status,a.verified_at,a.paused,
 s.material_status,s.incognia_mode,s.collection_mode,
 MAX(CASE WHEN c.endpoint='productSpecifics' THEN c.state END) AS details_state,
 MAX(CASE WHEN c.endpoint='shopInfo' THEN c.state END) AS shop_state,
 MAX(CASE WHEN c.endpoint='productList' THEN c.state END) AS menu_state,
 MAX(CASE WHEN c.endpoint='productRender' THEN c.state END) AS render_state,
 MAX(CASE WHEN c.endpoint='homeShopList' THEN c.state END) AS listing_state,
 MAX(CASE WHEN c.endpoint='accountInfo' THEN c.state END) AS account_info_state,
 MAX(c.observed_at) AS last_observation
FROM accounts a LEFT JOIN account_sessions s ON s.id=a.active_session_id
LEFT JOIN capabilities c ON c.session_id=s.id
GROUP BY a.id,a.label,a.user_id,a.region,a.identity_status,a.verified_at,a.paused,
 s.material_status,s.incognia_mode,s.collection_mode;
CREATE OR REPLACE VIEW account_dashboard AS
SELECT s.*,
 CASE
 WHEN s.material_status='needs_material' THEN '待材料'
 WHEN s.identity_status='expired' THEN '登录失效'
 WHEN s.paused=TRUE THEN '已暂停'
 WHEN s.details_state='available' THEN 'L1 详情可用'
 WHEN s.shop_state='available' OR s.menu_state='available' OR s.render_state='available' THEN 'L2 店铺或菜单可用'
 WHEN s.listing_state='available' THEN 'L3 店铺列表可用'
 WHEN s.account_info_state='available' AND s.details_state='cooldown' AND s.shop_state='cooldown' AND s.menu_state='cooldown' THEN 'L4 已测业务受限'
 ELSE '待验证'
 END AS observed_level
FROM account_status s;
CREATE TABLE IF NOT EXISTS account_profiles (
 account_id BIGINT UNSIGNED PRIMARY KEY,
 environment VARCHAR(16) NOT NULL DEFAULT 'test',
 updated_at DATETIME(6) NOT NULL,
 FOREIGN KEY(account_id) REFERENCES accounts(id),
 CHECK(environment IN ('test','production'))
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS account_tags (
 account_id BIGINT UNSIGNED NOT NULL, tag VARCHAR(64) NOT NULL,
 PRIMARY KEY(account_id,tag), INDEX tag_accounts(tag,account_id),
 FOREIGN KEY(account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS executions (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, run_id BIGINT UNSIGNED NOT NULL,
 environment VARCHAR(16) NOT NULL, selection JSON NOT NULL,
 account_ids JSON NOT NULL, endpoints JSON NOT NULL,
 max_requests INT UNSIGNED NOT NULL, delay_seconds DOUBLE NOT NULL,
 state VARCHAR(32) NOT NULL DEFAULT 'queued', stop_requested BOOLEAN NOT NULL DEFAULT FALSE,
 processed INT UNSIGNED NOT NULL DEFAULT 0, sent INT UNSIGNED NOT NULL DEFAULT 0,
 valid_count INT UNSIGNED NOT NULL DEFAULT 0,
 created_at DATETIME(6) NOT NULL, started_at DATETIME(6) NULL,
 heartbeat_at DATETIME(6) NULL, finished_at DATETIME(6) NULL,
 owner CHAR(36) NULL, stop_reason VARCHAR(100) NULL, export_summary JSON NULL,
 INDEX execution_queue(state,id), FOREIGN KEY(run_id) REFERENCES collection_runs(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS encrypted_settings (
 setting_key VARCHAR(80) PRIMARY KEY, encryption_key_id CHAR(16) NOT NULL,
 credential_blob LONGBLOB NOT NULL, updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS request_diagnostics (
 attempt_id CHAR(64) PRIMARY KEY,
 encryption_key_id CHAR(16) NOT NULL, credential_blob LONGBLOB NOT NULL,
 observed_at DATETIME(6) NOT NULL,
 FOREIGN KEY(attempt_id) REFERENCES request_attempts(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS proxy_refresh_events (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, route_key CHAR(64) NOT NULL,
 account_id BIGINT UNSIGNED NOT NULL, task_id BIGINT UNSIGNED NOT NULL,
 started_at DATETIME(6) NOT NULL, finished_at DATETIME(6) NULL,
 outcome VARCHAR(32) NOT NULL, http_status INT NULL, error_type VARCHAR(100) NULL,
 INDEX proxy_refresh_cooldown(route_key,started_at)
) ENGINE=InnoDB;
