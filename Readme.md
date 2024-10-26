# JWKS Server with SQLite Integration


This project implements a JSON Web Key Set (JWKS) server with a RESTful API for secure JWT authentication. It uses SQLite for RSA key storage, ensuring persistence across server restarts and protecting against SQL injection attacks through parameterized queries.

## Project Overview

This project extends a basic JWKS server by integrating SQLite for secure storage of private keys. The goal is to enhance the server's functionality and security, particularly against SQL injection attacks, by persisting private keys in a database.

## Objective
- Fortify the JWKS server against SQL injection.
- Persist private keys to ensure availability after server restarts.
- Use SQLite for database operations.

### Key Features
- **JWT Authentication**: Issues JWTs for user requests, simulating authentication. Supports valid and expired tokens based on a query parameter.
- **JWKS Endpoint**: Serves public keys for JWT verification through a JWKS JSON endpoint.
- **SQLite Integration**: Stores RSA private keys with expiration times in a SQLite database.
- **Parameterized Queries**: Protects against SQL injection by using safe, parameterized queries.
- **Robust Testing**: Validated with Gradebot for blackbox testing and achieves 98% unit test coverage.

## Project Structure

- **main.py**: Core server code with two main endpoints:
  - `POST /auth`: Issues JWTs based on user-supplied parameters. Supports valid and expired tokens.
  - `GET /.well-known/jwks.json`: Provides public keys in JWKS format.
- **totally_not_my_privateKeys.db**: SQLite database storing RSA private keys and their expiration times.
- **requirements.txt**: Lists dependencies, including `cryptography` for RSA handling and `pyjwt` for JWT management.

## Setup and Usage

### Prerequisites
- Python 3.x
- Required Python packages listed in `requirements.txt`.

### Installation

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt



# Running the Server
To start the server on localhost:8080, run:

python main.py

# API Endpoints
POST /auth
Returns a signed JWT. Optionally accepts an expired=true query parameter to return a token signed with an expired key.

GET /.well-known/jwks.json
Returns the JSON Web Key Set (JWKS) containing public keys for JWT verification.

# Testing
Gradebot Blackbox Testing
To ensure functionality, run the Gradebot client (if provided) in the same directory as main.py and totally_not_my_privateKeys.db:

gradebot.exe project2


# Unit Testing and Coverage
Run unit tests and check coverage:

coverage run -m unittest discover
coverage report
coverage html

To view the HTML coverage report:

start htmlcov\index.html
## Screenshots

- [Gradebot Output](Gradebot.png): Shows Gradebot rubric table and points awarded.!
- [Test Coverage Report](<Testsuite Coverage.png>): Shows the test coverage percentage and coverage details for `test_server.py`.
