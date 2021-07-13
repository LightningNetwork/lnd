package postgres

// Config holds postgres configuration data.
type Config struct {
	Dsn string `long:"dsn" description:"Database connection string."`
}
