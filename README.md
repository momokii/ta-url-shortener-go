# Golang Gin URL Shortener API

URL Shortener API with Postgresql and MongoDB
## Getting Started

### 1. Configure Environment Variables
Create a `.env` file in the root directory of the project and fill it with your configuration settings with basic values from `.example.env`.

### 2. Install Dependencies
Run the following command to ensure all necessary modules are installed:

```bash
go mod tidy
```

### 3. Start the Development Server
To start the development server, run:

```bash
go run main.go
```

This will start the server and automatically load changes when you rerun the command after making changes.

### 4. Start the Production Server
To start the server in production mode, you can build the binary and run it:

#### On Windows:
```bash
go build -o url-shortener.exe
url-shortener.exe
```

#### On Linux/macOS:
```bash
go build -o url-shortener
./url-shortener
```
