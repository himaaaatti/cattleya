
DOCKER	:=	docker
COMPOSE	:= 	docker-compose
MYSQL_ENV	:= mysql/mysql.env
MYSQL_ENV_TMPL 	:= $(MYSQL_ENV).tmpl

DOCKER_SERVICES	:= mysql #app

.SUFFIXES: run
run: $(MYSQL_ENV)
	$(COMPOSE) up -d

.SUFFIXES: env
env: $(MYSQL_ENV)

$(MYSQL_ENV): $(MYSQL_ENV_TMPL)
	cp $(MYSQL_ENV_TMPL) $(MYSQL_ENV)
	ln -s $(MYSQL_ENV) mysql.env

.SUFFIXES: connect_db
connect_db:
	$(COMPOSE) exec mysql /bin/bash

.SUFFIXES: stop
stop:
	$(COMPOSE) kill

.SUFFIXES: clean
clean:
	$(COMPOSE) down

