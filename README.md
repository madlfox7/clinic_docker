cp .env.example .env
export HOST_UID=$(id -u)
export HOST_GID=$(id -g)
docker compose up -d
# open http://localhost:8080


api/
  Dockerfile
  requirements.txt
  main.py
  templates/
    base.html
    home.html
    login.html
    me.html