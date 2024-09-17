package dynamo

import (
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"go-dynamo-demo/storage"
)

type DBRepository struct {
	db *dynamodb.DynamoDB
	// We use a single table structure
	tableName string
}

// NewClient creates a new *Client
// TODO: we are passing the DB client for now since the indexing-schema is handled outside this package
func NewClient(db *dynamodb.DynamoDB, tableName string) *storage.Client {
	return &storage.Client{
		Repository: &DBRepository{
			db:        db,
			tableName: tableName,
		},
	}
}
