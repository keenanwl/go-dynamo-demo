run:
	go build -o backend && ./backend

test:
	go test ./... -race -cover