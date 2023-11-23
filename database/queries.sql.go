// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0
// source: queries.sql

package database

import (
	"context"
)

const createCounter = `-- name: CreateCounter :exec
INSERT INTO counters (user_id, count) VALUES (?, 1)
`

func (q *Queries) CreateCounter(ctx context.Context, userID string) error {
	_, err := q.db.ExecContext(ctx, createCounter, userID)
	return err
}

const getCounter = `-- name: GetCounter :one
SELECT user_id, count FROM counters WHERE user_id = ? LIMIT 1
`

func (q *Queries) GetCounter(ctx context.Context, userID string) (Counter, error) {
	row := q.db.QueryRowContext(ctx, getCounter, userID)
	var i Counter
	err := row.Scan(&i.UserID, &i.Count)
	return i, err
}

const incrementCounter = `-- name: IncrementCounter :one
UPDATE counters SET count = count + 1 WHERE user_id = ? RETURNING count
`

func (q *Queries) IncrementCounter(ctx context.Context, userID string) (int64, error) {
	row := q.db.QueryRowContext(ctx, incrementCounter, userID)
	var count int64
	err := row.Scan(&count)
	return count, err
}