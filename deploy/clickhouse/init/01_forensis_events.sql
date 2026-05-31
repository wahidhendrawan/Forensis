CREATE DATABASE IF NOT EXISTS forensis;

CREATE TABLE IF NOT EXISTS forensis.events
(
  ingested_at DateTime,
  source_type LowCardinality(String),
  source_ip String,
  destination_ip String,
  indicator String,
  severity LowCardinality(String),
  message String,
  event_json String
)
ENGINE = MergeTree
ORDER BY (ingested_at, source_type);
