FROM mysql:5.7

ADD initial.sql /docker-entrypoint-initdb.d/initial.sql

ENTRYPOINT ["docker-entrypoint.sh"]
EXPOSE 3306
CMD ["mysqld"]
