package counter

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Darkness4/auth-htmx/database"
)

type Repository interface {
	Inc(ctx context.Context, userID string) (new int64, err error)
	Get(ctx context.Context, userID string) (int64, error)
}

func NewRepository(db *sql.DB) Repository {
	return &repository{
		Queries: database.New(db),
	}
}

type repository struct {
	*database.Queries
}

func (r *repository) Inc(ctx context.Context, userID string) (new int64, err error) {
	new, err = r.Queries.IncrementCounter(ctx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return new, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 1, r.Queries.CreateCounter(ctx, userID)
	}
	return new, err
}

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
