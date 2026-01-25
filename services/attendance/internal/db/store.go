package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	Pool    *pgxpool.Pool
	Queries *Queries
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{Pool: pool, Queries: New(pool)}
}

func (s *Store) WithTx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	queries := s.Queries.WithTx(tx)
	if err := fn(queries); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}
