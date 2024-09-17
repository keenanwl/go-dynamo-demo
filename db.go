package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"log"
)

const (
	tableName  = "EntityTable"
	emailIndex = "EmailIndex"
)

func setupDynamoDB() *dynamodb.DynamoDB {
	// Initialize a session that the SDK will use to load
	// Uses local Dynamo instance for now
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Endpoint:    aws.String("http://localhost:8000"),
			Region:      aws.String("ap-southeast-1"),
			Credentials: credentials.NewStaticCredentials("fake", "fake", ""),
		},
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	// Check if the table exists
	_, err := svc.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})

	// TODO: check for other error types
	if err != nil {
		// If the table doesn't exist, create it
		_, err = svc.CreateTable(&dynamodb.CreateTableInput{
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("PK"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("SK"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("email"),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("PK"),
					KeyType:       aws.String("HASH"),
				},
				{
					AttributeName: aws.String("SK"),
					KeyType:       aws.String("RANGE"),
				},
			},
			GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
				{
					IndexName: aws.String("EmailIndex"),
					KeySchema: []*dynamodb.KeySchemaElement{
						{
							AttributeName: aws.String("email"),
							KeyType:       aws.String("HASH"),
						},
					},
					Projection: &dynamodb.Projection{
						ProjectionType: aws.String("ALL"),
					},
					ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
						ReadCapacityUnits:  aws.Int64(5),
						WriteCapacityUnits: aws.Int64(5),
					},
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
			TableName: aws.String(tableName),
		})
		if err != nil {
			log.Fatalf("error calling CreateTable: %s", err)
		}

		log.Println("created table", tableName)
	}

	return svc
}
