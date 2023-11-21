// Package counter handles the logic of a counter.
package counter

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Darkness4/auth-htmx/database"
)

// Repository defines the counter methods.
type Repository interface {
	Inc(ctx context.Context, userID string) (new int64, err error)
	Get(ctx context.Context, userID string) (int64, error)
}

// NewRepository wraps around a SQL database to execute the counter methods.
func NewRepository(db *sql.DB) Repository {
	return &repository{
		Queries: database.New(db),
	}
}

type repository struct {
	*database.Queries
}

// Inc increments the counter of a user in the database by one.
func (r *repository) Inc(ctx context.Context, userID string) (newValue int64, err error) {
	newValue, err = r.Queries.IncrementCounter(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return newValue, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 1, r.Queries.CreateCounter(ctx, userID)
	}
	return newValue, err
}

// Get the value of the counter of a user from the database.
func (r *repository) Get(ctx context.Context, userID string) (int64, error) {
	counter, err := r.Queries.GetCounter(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return counter.Count, nil
}
