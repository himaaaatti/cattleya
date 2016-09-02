DOCKER	:=	docker
COMPOSE	:= 	docker-compose

GO	:= go

DOCKER_SERVICES	:= mysql app
ENV_FILES	:= $(foreach name, $(DOCKER_SERVICES), $(name)/$(name).env)

APPLICATION	:= app/app
APP_FILES	:= main.go
APP_SOURCE	:= $(foreach f, $(APP_FILES), app/$(f))

.SUFFIXES: run
run: $(ENV_FILES) build
	$(COMPOSE) up -d

.SUFFIXES: env
env: $(ENV_FILES)

$(ENV_FILES): 
	for f in $(DOCKER_SERVICES); do\
		cp $$f/$$f.env.tmpl $$f/$$f.env; \
		ln -s $$f/$$f.env $$f.env;\
	done

.SUFFIXES: app
app: $(APPLICATION)
$(APPLICATION): $(APP_SOURCE)
	(cd app; $(GO) get; $(GO) build)

.SUFFIXES: build
build: $(APPLICATION) 
	$(COMPOSE) build

.SUFFIXES: connect_db
connect_db:
	$(COMPOSE) exec mysql /bin/bash

.SUFFIXES: kill
kill:
	$(COMPOSE) kill

.SUFFIXES: develop
develop:
	(cd mysql; docker build ./ -t mysql:cattleya; docker run -d -p"3306:3306" --env-file=mysql.env mysql:cattleya)
	docker run -d -p"6379:6379" redis:3.0

.SUFFIXES: clean
clean:
	rm -f *.env $(APPLICATION)
	$(COMPOSE) down
	

