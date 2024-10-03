package dynamo

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/google/uuid"
	"go-dynamo-demo/storage"
	"golang.org/x/crypto/bcrypt"
)

// DBUser extends User with DynamoDB-specific fields
type DBUser struct {
	storage.User
	PK string
	SK string
}

func (repo *DBRepository) Login(ctx context.Context, credentials storage.LoginCredentials) (*storage.User, error) {
	user, err := repo.GetUserByEmail(ctx, credentials.Email)
	if err != nil {
		// If the user is not found, return invalid credentials error
		// This is to prevent user enumeration
		return nil, storage.ErrInvalidCredentials
	}

	// Check the password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		// If the password doesn't match, return invalid credentials error
		return nil, storage.ErrInvalidCredentials
	}

	// Clear the password hash before returning the user
	user.Password = ""

	return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (repo *DBRepository) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	// We'll need to use a GSI (Global Secondary Index) to query by email efficiently
	// Assuming you have a GSI with email as the partition key

	input := &dynamodb.QueryInput{
		TableName:              aws.String(repo.tableName),
		IndexName:              aws.String("EmailIndex"), // Replace with your actual GSI name
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":email": {S: aws.String(email)},
		},
		Limit: aws.Int64(1), // We only need one item
	}

	result, err := repo.db.QueryWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}

	if len(result.Items) == 0 {
		return nil, storage.ErrInvalidCredentials
	}

	var dbUser DBUser
	err = dynamodbattribute.UnmarshalMap(result.Items[0], &dbUser)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DynamoDB result: %w", err)
	}

	return &dbUser.User, nil
}

func (repo *DBRepository) CreateUser(ctx context.Context, user *storage.User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	// TODO: Prevent duplicates. Not atomic; needs replacing.
	if _, err := repo.GetUserByEmail(ctx, user.Email); err == nil {
		return nil
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Create a copy of the user with the hashed password
	userWithHashedPassword := *user
	userWithHashedPassword.Password = string(hashedPassword)

	dbUser := DBUser{
		User: userWithHashedPassword,
		PK:   fmt.Sprintf("USER#%s", user.ID),
		SK:   fmt.Sprintf("METADATA#USER#%s", user.ID),
	}

	av, err := dynamodbattribute.MarshalMap(dbUser)
	if err != nil {
		return fmt.Errorf("failed to marshal User: %w", err)
	}

	// Attempt at building in the Dynamo dupe check
	_, err = repo.db.TransactWriteItemsWithContext(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []*dynamodb.TransactWriteItem{
			{
				// Insert new user
				Put: &dynamodb.Put{
					TableName: aws.String(repo.tableName),
					Item:      av,
				},
			},
		},
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return fmt.Errorf("user with email %s already exists", user.Email)
			case dynamodb.ErrCodeResourceNotFoundException:
				return fmt.Errorf("table %s not found: %w", repo.tableName, err)
			}
		}
		return fmt.Errorf("failed to create user in DynamoDB: %w", err)
	}

	// Clear the password in the original user struct for security
	user.Password = ""

	return nil
}

func (repo *DBRepository) GetUser(ctx context.Context, id string) (*storage.User, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"PK": {S: aws.String(fmt.Sprintf("USER#%s", id))},
			"SK": {S: aws.String(fmt.Sprintf("METADATA#USER#%s", id))},
		},
		TableName: aws.String(repo.tableName),
	}

	// TODO: timeout ctx?
	result, err := repo.db.GetItemWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from DynamoDB: %w", err)
	}

	if result.Item == nil {
		return nil, storage.ErrUserNotFound
	}

	var dbUser DBUser
	err = dynamodbattribute.UnmarshalMap(result.Item, &dbUser)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DynamoDB result: %w", err)
	}

	return &dbUser.User, nil
}

func (repo *DBRepository) GetUsers(ctx context.Context) ([]*storage.User, error) {
	input := &dynamodb.ScanInput{
		TableName:        aws.String(repo.tableName),
		FilterExpression: aws.String("begins_with(PK, :pkPrefix)"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pkPrefix": {
				S: aws.String("USER#"),
			},
		},
	}

	var users []*storage.User

	for {
		result, err := repo.db.ScanWithContext(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to scan users from DynamoDB: %w", err)
		}

		var dbUsers []DBUser
		err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &dbUsers)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal users from DynamoDB: %w", err)
		}

		for _, dbUser := range dbUsers {
			user := &dbUser.User
			user.Password = "" // Remove password for security
			users = append(users, user)
		}

		// If LastEvaluatedKey is nil, we've reached the end of the results
		if result.LastEvaluatedKey == nil {
			break
		}

		// Set the start key for the next scan to the last evaluated key
		input.ExclusiveStartKey = result.LastEvaluatedKey
	}

	return users, nil
}

func (repo *DBRepository) UpdateUser(ctx context.Context, user *storage.User) error {
	dbUser := DBUser{
		User: *user,
		PK:   fmt.Sprintf("USER#%s", user.ID),
		SK:   fmt.Sprintf("METADATA#USER#%s", user.ID),
	}

	av, err := dynamodbattribute.MarshalMap(dbUser)
	if err != nil {
		return fmt.Errorf("failed to marshal User: %w", err)
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(repo.tableName),
	}

	_, err = repo.db.PutItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to update user in DynamoDB: %w", err)
	}

	return nil
}

func (repo *DBRepository) DeleteUser(ctx context.Context, id string) error {
	input := &dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"PK": {S: aws.String(fmt.Sprintf("USER#%s", id))},
			"SK": {S: aws.String(fmt.Sprintf("METADATA#USER#%s", id))},
		},
		TableName: aws.String(repo.tableName),
	}

	_, err := repo.db.DeleteItemWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete user from DynamoDB: %w", err)
	}

	return nil
}
