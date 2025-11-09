Test with various databases
===========================

MySQL
-----

The simplest way to test with MySQL is to use the official [MySQL docker image](https://registry.hub.docker.com/_/mysql/).

Start MySQL:

    docker run --name mysql -e MYSQL_DATABASE=iamshield -e MYSQL_USER=iamshield -e MYSQL_PASSWORD=iamshield -e MYSQL_ROOT_PASSWORD=iamshield -d mysql
   
Run tests:

    mvn install -Diamshield.connectionsJpa.url=jdbc:mysql://`docker inspect --format '{{ .NetworkSettings.IPAddress }}' mysql`/iamshield -Diamshield.connectionsJpa.driver=com.mysql.jdbc.Driver -Diamshield.connectionsJpa.user=iamshield -Diamshield.connectionsJpa.password=iamshield    
    
Stop MySQl:

    docker rm -f mysql
    
    
PostgreSQL
----------

The simplest way to test with PostgreSQL is to use the official [PostgreSQL docker image](https://registry.hub.docker.com/_/postgres/).

Start PostgreSQL:

    docker run --name postgres -e POSTGRES_DATABASE=iamshield -e POSTGRES_USER=iamshield -e POSTGRES_PASSWORD=iamshield -e POSTGRES_ROOT_PASSWORD=iamshield -d postgres
   
Run tests:

    mvn install -Diamshield.connectionsJpa.url=jdbc:postgresql://`docker inspect --format '{{ .NetworkSettings.IPAddress }}' postgres`:5432/iamshield -Diamshield.connectionsJpa.driver=org.postgresql.Driver -Diamshield.connectionsJpa.user=iamshield -Diamshield.connectionsJpa.password=iamshield    
    
Stop PostgreSQL:

    docker rm -f postgres
    
MariaDB
-------

The simplest way to test with MariaDB is to use the official [MariaDB docker image](https://registry.hub.docker.com/_/mariadb/).

Start MariaDB:

    docker run --name mariadb -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=iamshield -e MYSQL_USER=iamshield -e MYSQL_PASSWORD=iamshield -d mariadb:10.1
   
Run tests:

    mvn install -Diamshield.connectionsJpa.url=jdbc:mariadb://`docker inspect --format '{{ .NetworkSettings.IPAddress }}' mariadb`/iamshield -Diamshield.connectionsJpa.driver=org.mariadb.jdbc.Driver -Diamshield.connectionsJpa.user=iamshield -Diamshield.connectionsJpa.password=iamshield    
    
Stop MySQl:

    docker rm -f mariadb

TiDB
-----

The simplest way to test with TiDB is to use the official [TiDB docker image](https://hub.docker.com/r/pingcap/tidb).

Start TiDB:

    docker run --name tidb -p 4000:4000 -d pingcap/tidb:v8.5.2

Run tests:

    mvn install -Diamshield.connectionsJpa.url=jdbc:mysql://`docker inspect --format '{{ .NetworkSettings.IPAddress }}' tidb`:4000/test -Diamshield.connectionsJpa.driver=com.mysql.jdbc.Driver -Diamshield.connectionsJpa.user=root -Diamshield.connectionsJpa.password=    

Stop TiDB:

    docker rm -f tidb

Using built-in profiles to run database tests using docker containers
-------

The project provides specific profiles to run database tests using containers. Below is a just a sample of implemented profiles. In order to get a full list, please invoke (`mvn help:all-profiles -pl testsuite/integration-arquillian | grep -- db-`):

* `db-mysql`
* `db-postgres`

As an example, to run tests using a MySQL docker container on Undertow auth-server:

    mvn -f testsuite/integration-arquillian clean verify -Pdb-mysql

If you want to run tests using a pre-configured Keycloak distribution (instead of Undertow):

    mvn -f testsuite/integration-arquillian clean verify -Pdb-mysql,jpa,auth-server-quarkus

Note that you must always activate the `jpa` profile when using auth-server-quarkus.

If the mvn command fails for any reason, it may also fail to remove the container which
must be then removed manually.

For Oracle databases, the images are not publicly available due to licensing restrictions. 

Build the Docker image per instructions at
https://github.com/oracle/docker-images/tree/main/OracleDatabase.
Update the property `docker.database.image` if you used a different
name or tag for the image.

Note that Docker containers may occupy some space even after termination, and
especially with databases that might be easily a gigabyte. It is thus
advisable to run `docker system prune` occasionally to reclaim that space.
