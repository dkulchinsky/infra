PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE migrations (id VARCHAR(255) PRIMARY KEY);
INSERT INTO migrations VALUES('SCHEMA_INIT');
INSERT INTO migrations VALUES('202203231621');
INSERT INTO migrations VALUES('202203241643');
INSERT INTO migrations VALUES('202203301642');
INSERT INTO migrations VALUES('202203301652');
INSERT INTO migrations VALUES('202203301643');
INSERT INTO migrations VALUES('202203301644');
INSERT INTO migrations VALUES('202203301645');
INSERT INTO migrations VALUES('202203301646');
INSERT INTO migrations VALUES('202203301647');
INSERT INTO migrations VALUES('202203301648');
INSERT INTO migrations VALUES('202204061643');
INSERT INTO migrations VALUES('202204111503');
INSERT INTO migrations VALUES('202204181613');
CREATE TABLE `groups` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`provider_id` integer,PRIMARY KEY (`id`));
CREATE TABLE `identities_groups` (`group_id` integer,`identity_id` integer,PRIMARY KEY (`group_id`,`identity_id`),CONSTRAINT `fk_identities_groups_group` FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`),CONSTRAINT `fk_identities_groups_identity` FOREIGN KEY (`identity_id`) REFERENCES `identities`(`id`));
CREATE TABLE `grants` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`subject` text,`privilege` text,`resource` text,`created_by` integer,PRIMARY KEY (`id`));
CREATE TABLE `providers` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`url` text,`client_id` text,`client_secret` text,`created_by` integer,`scopes` text,`auth_url` text,PRIMARY KEY (`id`));
CREATE TABLE `provider_tokens` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`user_id` integer,`provider_id` integer,`redirect_url` text,`access_token` text,`refresh_token` text,`expires_at` datetime,PRIMARY KEY (`id`));
CREATE TABLE `destinations` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`unique_id` text,`connection_url` text,`connection_ca` text,PRIMARY KEY (`id`));
CREATE TABLE `access_keys` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`name` text,`issued_for` integer,`expires_at` datetime,`extension` integer,`extension_deadline` datetime,`key_id` text,`secret_checksum` blob,PRIMARY KEY (`id`));
CREATE TABLE `settings` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`private_jwk` blob,`public_jwk` blob,`setup_required` numeric,`signup_enabled` numeric,PRIMARY KEY (`id`));
INSERT INTO settings VALUES(36869170022129664,'2022-04-12 17:44:55.129594012+00:00','2022-04-12 17:44:55.129594012+00:00',NULL,X'7b22757365223a22736967222c226b7479223a224f4b50222c226b6964223a22706f66744a5a75365a6b617a45684a54336a5350587a7461635f49715468443470786965426d5a593834343d222c22637276223a2245643235353139222c22616c67223a2245443235353139222c2278223a22376d426b6a474b3463626b64506f6b70765465376b6a372d4e556a4434467a4b46634234737742374c3867222c2264223a227456556257634a66724b7246636e4e74396a6a55687a355935737a3947315472564948434539366b727949227d',X'7b22757365223a22736967222c226b7479223a224f4b50222c226b6964223a22706f66744a5a75365a6b617a45684a54336a5350587a7461635f49715468443470786965426d5a593834343d222c22637276223a2245643235353139222c22616c67223a2245443235353139222c2278223a22376d426b6a474b3463626b64506f6b70765465376b6a372d4e556a4434467a4b46634234737742374c3867227d',0,NULL);
CREATE TABLE `encryption_keys` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`key_id` integer,`name` text,`encrypted` blob,`algorithm` text,`root_key_id` text,PRIMARY KEY (`id`));
CREATE TABLE `trusted_certificates` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`key_algorithm` text,`signing_algorithm` text,`public_key` text,`cert_pem` blob,`identity` text,`expires_at` datetime,`one_time_use` numeric,PRIMARY KEY (`id`));
CREATE TABLE `root_certificates` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`key_algorithm` text,`signing_algorithm` text,`public_key` text,`private_key` text,`signed_cert` text,`expires_at` datetime,PRIMARY KEY (`id`));
CREATE TABLE `credentials` (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`identity_id` integer,`password_hash` blob,`one_time_password` numeric,`one_time_password_used` numeric,PRIMARY KEY (`id`));
CREATE TABLE IF NOT EXISTS "identities" (`id` integer,`created_at` datetime,`updated_at` datetime,`deleted_at` datetime,`kind` text,`name` text,`last_seen_at` datetime,`provider_id` integer,PRIMARY KEY (`id`),CONSTRAINT `fk_providers_users` FOREIGN KEY (`provider_id`) REFERENCES `providers`(`id`));
CREATE UNIQUE INDEX `idx_groups_name_provider_id` ON `groups`(`name`,`provider_id`) WHERE deleted_at is NULL;
CREATE UNIQUE INDEX `idx_providers_name` ON `providers`(`name`) WHERE deleted_at is NULL;
CREATE UNIQUE INDEX `idx_destinations_unique_id` ON `destinations`(`unique_id`) WHERE deleted_at is NULL;
CREATE UNIQUE INDEX `idx_access_keys_key_id` ON `access_keys`(`key_id`) WHERE deleted_at is NULL;
CREATE UNIQUE INDEX `idx_access_keys_name` ON `access_keys`(`name`) WHERE deleted_at is NULL;
CREATE UNIQUE INDEX `idx_encryption_keys_key_id` ON `encryption_keys`(`key_id`);
CREATE UNIQUE INDEX `idx_credentials_identity_id` ON `credentials`(`identity_id`) WHERE deleted_at is NULL;
COMMIT;