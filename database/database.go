// The package database handles the methods and definition to manipulate a database.
package database

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/*.sql
var migrations embed.FS

// InitialMigration migrate a sqlite3 database if necessary.
func InitialMigration(db *sql.DB) error {
	dbDriver, err := sqlite.WithInstance(db, &sqlite.Config{
		NoTxWrap: true,
	})
	if err != nil {
		log.Err(err).Msg("failed to attach db")
		return err
	}
	iofsDriver, err := iofs.New(migrations, "migrations")
	if err != nil {
		log.Err(err).Msg("failed to open migrations")
		return err
	}
	defer iofsDriver.Close()
	m, err := migrate.NewWithInstance(
		"iofs",
		iofsDriver,
		"sqlite",
		dbDriver,
	)
	if err != nil {
		log.Err(err).Msg("failed to create new db instance")
		return err
	}
	if version, dirty, err := m.Version(); err == migrate.ErrNilVersion {
		log.Warn().Msg("No migrations detected. Attempting initial migration...")
		if err = m.Up(); err != nil {
			panic(fmt.Errorf("failed to migrate db: %w", err))
		}
		log.Info().Msg("DB migrated.")
	} else if dirty {
		panic("db is in dirty state.")
	} else if err != nil {
		panic(fmt.Errorf("failed to fetch DB version: %w", err))
	} else {
		log.Info().Uint("version", version).Msg("DB version detected.")
		if newVersion, err := iofsDriver.Next(version); err != nil {
			log.Info().Uint("version", version).Msg("Latest DB version.")
		} else {
			log.Warn().Uint("actual", version).Uint("new", newVersion).Msg("New DB version detected. Attempting automatic migration...")
			if err = m.Up(); err != nil {
				panic(fmt.Errorf("failed to migrate db: %w", err))
			}
			log.Info().Msg("DB migrated.")
		}
	}
	return nil
}
