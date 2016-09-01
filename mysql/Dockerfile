FROM mysql:5.7

RUN set -x && apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

ADD initial.sql /docker-entrypoint-initdb.d/initial.sql

ENTRYPOINT ["docker-entrypoint.sh"]
EXPOSE 3306
CMD ["mysqld"]
