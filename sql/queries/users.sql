-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (gen_random_uuid(), NOW(), NOW(), $1, $2)
RETURNING *;

-- name: GetUser :one
SELECT *
FROM users
WHERE id =$1;

-- name: GetUserByEmail :one
SELECT *
FROM users
Where email =$1;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: UpdateUser :one
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpgradeToChirpyRed :one
UPDATE users
SET updated_at = NOW(), is_chirpy_red = TRUE
WHERE id = $1
RETURNING *;
