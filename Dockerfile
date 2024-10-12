# Step 1: Build the Go application
# Use the official Golang image to build the application
FROM golang:1.20 AS builder

# Set the current working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files first (for better caching)
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the rest of the application code to the container
COPY . .

# Build the application
RUN go build -o main .

# Step 2: Create a minimal image to run the application
# Use a minimal base image for production
FROM debian:bullseye-slim

# Install PostgreSQL client (optional, if your app needs it)
RUN apt-get update && apt-get install -y postgresql-client ca-certificates && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the built application from the previous stage
COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Expose the port that the application will run on
EXPOSE 8080

# Define the command to run the application
CMD ["./main"]