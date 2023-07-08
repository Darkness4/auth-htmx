package counter

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Darkness4/auth-htmx/database/models"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

type Repository interface {
	Inc(ctx context.Context, userID string) (new int64, err error)
	Get(ctx context.Context, userID string) (int64, error)
}

func NewRepository(db *sql.DB) Repository {
	return &repository{db}
}

type repository struct {
	*sql.DB
}

func (r *repository) Inc(ctx context.Context, userID string) (new int64, err error) {
	counter, err := models.Counters(models.CounterWhere.UserID.EQ(userID)).One(ctx, r.DB)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if counter == nil {
		counter = &models.Counter{
			UserID: userID,
			Count:  0,
		}
	}
	counter.Count++
	return counter.Count, counter.Upsert(
		ctx,
		r.DB,
		true,
		[]string{models.CounterColumns.UserID},
		boil.Whitelist(models.CounterColumns.Count),
		boil.Infer(),
	)
}

func (r *repository) Get(ctx context.Context, userID string) (int64, error) {
	counter, err := models.Counters(models.CounterWhere.UserID.EQ(userID)).One(ctx, r.DB)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return counter.Count, nil
}
