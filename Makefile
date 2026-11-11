.PHONY: start clean fclean stop restart

start:
	cp -n .env.example .env
	docker compose down -v
	./scripts/init_secrets.sh && docker compose up --build -d

clean:
	docker compose down

fclean:
	docker compose down -v
	docker system prune -a
	docker system df

stop:
	docker compose stop

restart:
	docker compose restart
