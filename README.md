cp .env.example .env
export HOST_UID=$(id -u)
export HOST_GID=$(id -g)
docker compose up -d
# open http://localhost:8080
