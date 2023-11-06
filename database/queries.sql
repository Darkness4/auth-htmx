-- name: GetCounter :one
SELECT * FROM counters WHERE user_id = ? LIMIT 1;

-- name: IncrementCounter :one
UPDATE counters SET count = count + 1 WHERE user_id = ? RETURNING count;

-- name: CreateCounter :exec
INSERT INTO counters (user_id, count) VALUES (?, 1);
