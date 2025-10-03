# IAMShield Deployment Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Server Requirements](#server-requirements)
4. [Installation Methods](#installation-methods)
5. [Configuration](#configuration)
6. [Production Deployment](#production-deployment)
7. [High Availability Setup](#high-availability-setup)
8. [Security Considerations](#security-considerations)
9. [Monitoring & Maintenance](#monitoring--maintenance)
10. [Troubleshooting](#troubleshooting)

---

## Overview

IAMShield is an open-source Identity and Access Management (IAM) solution that provides:
- Single Sign-On (SSO)
- User Authentication & Authorization
- Identity Brokering & Social Login
- Multi-factor Authentication (MFA)
- Fine-grained Authorization
- User Federation (LDAP/Active Directory)
- Standards Support (OIDC, SAML 2.0, OAuth 2.0)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Recommended Version | Purpose |
|----------|----------------|---------------------|---------|
| **Java JDK** | 17 | 21 (LTS) | Runtime environment |
| **Database** | See below | PostgreSQL 14+ | Data persistence |
| **Operating System** | RHEL 8 / Ubuntu 20.04 | RHEL 9 / Ubuntu 24.04 | Server OS |

### Supported Databases

| Database | Supported Versions | Production Ready |
|----------|-------------------|------------------|
| PostgreSQL | 12, 13, 14, 15, 16 | ✅ Recommended |
| MySQL | 8.0+ | ✅ Yes |
| MariaDB | 10.5, 10.6, 10.11 | ✅ Yes |
| Oracle | 19c, 21c | ✅ Yes |
| MS SQL Server | 2019, 2022 | ✅ Yes |

---

## Server Requirements

### Development Environment

| Component | Specification |
|-----------|---------------|
| CPU | 2 vCPU |
| RAM | 2 GB |
| Disk | 1 GB |
| Database | H2 (embedded) |
| Network | Basic connectivity |

### Production Environment

#### Small Deployment (< 10,000 users)

| Component | Specification |
|-----------|---------------|
| CPU | 4-6 vCPU |
| RAM | 4 GB |
| Disk | 5 GB SSD |
| Database | PostgreSQL (2 vCPU, 4 GB RAM, 20 GB SSD) |
| Network | 100 Mbps |

#### Medium Deployment (10,000 - 100,000 users)

| Component | Specification |
|-----------|---------------|
| CPU | 8-12 vCPU |
| RAM | 8 GB |
| Disk | 10 GB SSD |
| Database | PostgreSQL (4 vCPU, 8 GB RAM, 50 GB SSD) |
| Network | 500 Mbps |

#### Large Deployment (> 100,000 users)

| Component | Specification |
|-----------|---------------|
| CPU | 16+ vCPU |
| RAM | 16 GB |
| Disk | 20 GB SSD |
| Database | PostgreSQL Cluster (8 vCPU, 16 GB RAM, 100+ GB SSD) |
| Network | 1 Gbps+ |

### Performance Benchmarks

Based on production testing:

| Operation | Throughput | Resource Usage |
|-----------|-----------|----------------|
| User Logins | 24 logins/sec | 3 vCPU |
| Token Refresh | 350 refreshes/sec | 1 vCPU |
| Client Credentials | 450 grants/sec | 1 vCPU |

**Note:** Add 150% CPU headroom for handling traffic spikes.

---

## Installation Methods

### Method 1: Standalone Installation (Recommended for Getting Started)

#### Step 1: Install Java

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install openjdk-21-jdk
java -version  # Verify installation
```

**Linux (RHEL/CentOS):**
```bash
sudo yum install java-21-openjdk
java -version  # Verify installation
```

**Windows:**
- Download OpenJDK 21 from https://adoptium.net/
- Install and set JAVA_HOME environment variable
- Add Java to PATH

#### Step 2: Download IAMShield

```bash
# Download the distribution
wget https://your-server/iamshield-<version>.tar.gz

# Extract
tar -xzf iamshield-<version>.tar.gz
cd iamshield-<version>
```

#### Step 3: Start in Development Mode

```bash
# Linux/Mac
./bin/iamshield.sh start-dev

# Windows
bin\iamshield.bat start-dev
```

Access IAMShield at: http://localhost:8080

**First Login:**
- Create admin user through the welcome page
- Default credentials will be set during first access

---

### Method 2: Docker Installation

#### Prerequisites
- Docker 20.10+
- Docker Compose (optional)

#### Quick Start with Docker

```bash
# Run with H2 database (development)
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/iamshield/iamshield:latest start-dev
```

#### Production Docker Setup

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: iamshield
      POSTGRES_USER: iamshield
      POSTGRES_PASSWORD: change_me_in_production
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - iamshield-network

  iamshield:
    image: quay.io/iamshield/iamshield:latest
    command: start
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/iamshield
      KC_DB_USERNAME: iamshield
      KC_DB_PASSWORD: change_me_in_production
      KC_HOSTNAME: iam.yourdomain.com
      KC_PROXY: edge
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: change_me_in_production
    ports:
      - "8080:8080"
    depends_on:
      - postgres
    networks:
      - iamshield-network

volumes:
  postgres_data:

networks:
  iamshield-network:
```

Start with:
```bash
docker-compose up -d
```

---

### Method 3: Kubernetes Deployment

#### Prerequisites
- Kubernetes 1.21+
- kubectl configured
- Persistent storage provisioner

#### Using Kubernetes Operator

```bash
# Install the operator
kubectl apply -f https://raw.githubusercontent.com/iamshield/iamshield-operator/main/deploy/operator.yaml

# Create IAMShield instance
kubectl apply -f - <<EOF
apiVersion: k8s.iamshield.org/v2alpha1
kind: Keycloak
metadata:
  name: iamshield-instance
spec:
  instances: 3
  db:
    vendor: postgres
    host: postgres-service
    database: iamshield
    usernameSecret:
      name: db-credentials
      key: username
    passwordSecret:
      name: db-credentials
      key: password
  http:
    tlsSecret: iamshield-tls
  hostname:
    hostname: iam.yourdomain.com
EOF
```

#### Manual Kubernetes Deployment

Create `iamshield-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: iamshield
spec:
  replicas: 3
  selector:
    matchLabels:
      app: iamshield
  template:
    metadata:
      labels:
        app: iamshield
    spec:
      containers:
      - name: iamshield
        image: quay.io/iamshield/iamshield:latest
        args: ["start"]
        env:
        - name: KC_DB
          value: "postgres"
        - name: KC_DB_URL
          value: "jdbc:postgresql://postgres:5432/iamshield"
        - name: KC_DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        - name: KC_HOSTNAME
          value: "iam.yourdomain.com"
        - name: KC_PROXY
          value: "edge"
        - name: KEYCLOAK_ADMIN
          valueFrom:
            secretKeyRef:
              name: admin-credentials
              key: username
        - name: KEYCLOAK_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: admin-credentials
              key: password
        - name: JAVA_OPTS_KC_HEAP
          value: "-Xms2g -Xmx4g"
        ports:
        - containerPort: 8080
        resources:
          requests:
            cpu: "6"
            memory: "3Gi"
          limits:
            memory: "4Gi"
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: iamshield
spec:
  type: LoadBalancer
  selector:
    app: iamshield
  ports:
  - port: 443
    targetPort: 8080
```

Deploy:
```bash
kubectl apply -f iamshield-deployment.yaml
```

---

## Configuration

### Database Setup

#### PostgreSQL Setup

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql

postgres=# CREATE DATABASE iamshield;
postgres=# CREATE USER iamshield WITH ENCRYPTED PASSWORD 'change_me';
postgres=# GRANT ALL PRIVILEGES ON DATABASE iamshield TO iamshield;
postgres=# \q
```

#### Database Connection Configuration

**Option 1: Environment Variables**
```bash
export KC_DB=postgres
export KC_DB_URL=jdbc:postgresql://localhost:5432/iamshield
export KC_DB_USERNAME=iamshield
export KC_DB_PASSWORD=change_me
```

**Option 2: Configuration File** (`conf/iamshield.conf`)
```properties
db=postgres
db-url=jdbc:postgresql://localhost:5432/iamshield
db-username=iamshield
db-password=change_me
db-pool-initial-size=30
db-pool-max-size=30
db-pool-min-size=30
```

### SSL/TLS Configuration

#### Generate or Obtain SSL Certificate

**Using Let's Encrypt (Recommended):**
```bash
sudo apt install certbot
sudo certbot certonly --standalone -d iam.yourdomain.com
```

Certificates will be at:
- Certificate: `/etc/letsencrypt/live/iam.yourdomain.com/fullchain.pem`
- Private Key: `/etc/letsencrypt/live/iam.yourdomain.com/privkey.pem`

#### Configure HTTPS

**Option 1: Direct HTTPS**
```bash
bin/iamshield.sh start \
  --https-certificate-file=/etc/letsencrypt/live/iam.yourdomain.com/fullchain.pem \
  --https-certificate-key-file=/etc/letsencrypt/live/iam.yourdomain.com/privkey.pem \
  --hostname=iam.yourdomain.com
```

**Option 2: Reverse Proxy (Nginx)**

Create `/etc/nginx/sites-available/iamshield`:
```nginx
upstream iamshield {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name iam.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name iam.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/iam.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/iam.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://iamshield;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/iamshield /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

Configure IAMShield for proxy:
```bash
bin/iamshield.sh start \
  --hostname=iam.yourdomain.com \
  --proxy=edge \
  --http-enabled=true
```

### JVM Memory Configuration

**Environment Variable:**
```bash
export JAVA_OPTS_KC_HEAP="-Xms2g -Xmx4g"
```

**Recommendations:**
- Small deployment: `-Xms1g -Xmx2g`
- Medium deployment: `-Xms2g -Xmx4g`
- Large deployment: `-Xms4g -Xmx8g`

---

## Production Deployment

### Pre-Production Checklist

- [ ] Java 17+ installed (Java 21 recommended)
- [ ] External database configured (PostgreSQL recommended)
- [ ] SSL/TLS certificates obtained
- [ ] Hostname/domain configured
- [ ] Firewall rules configured
- [ ] Database backups configured
- [ ] Monitoring setup (optional but recommended)
- [ ] Load balancer configured (for HA)

### Build Optimized Configuration

```bash
# Build with production features
bin/iamshield.sh build \
  --db=postgres \
  --features=token-exchange,admin-fine-grained-authz \
  --health-enabled=true \
  --metrics-enabled=true
```

### Start Production Server

**Full Command:**
```bash
bin/iamshield.sh start \
  --hostname=iam.yourdomain.com \
  --db=postgres \
  --db-url=jdbc:postgresql://db-server:5432/iamshield \
  --db-username=iamshield \
  --db-password='SecurePassword123!' \
  --https-certificate-file=/path/to/cert.pem \
  --https-certificate-key-file=/path/to/key.pem \
  --proxy=edge \
  --log-level=INFO \
  --health-enabled=true \
  --metrics-enabled=true
```

### Systemd Service (Linux)

Create `/etc/systemd/system/iamshield.service`:

```ini
[Unit]
Description=IAMShield Server
After=network.target postgresql.service

[Service]
Type=simple
User=iamshield
Group=iamshield
WorkingDirectory=/opt/iamshield
Environment="JAVA_OPTS_KC_HEAP=-Xms2g -Xmx4g"
Environment="KC_DB=postgres"
Environment="KC_DB_URL=jdbc:postgresql://localhost:5432/iamshield"
Environment="KC_DB_USERNAME=iamshield"
Environment="KC_DB_PASSWORD=change_me"
Environment="KC_HOSTNAME=iam.yourdomain.com"
Environment="KC_PROXY=edge"
ExecStart=/opt/iamshield/bin/iamshield.sh start
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable iamshield
sudo systemctl start iamshield
sudo systemctl status iamshield
```

### Logs

View logs:
```bash
# Systemd
sudo journalctl -u iamshield -f

# Direct logs
tail -f data/log/iamshield.log
```

---

## High Availability Setup

### Architecture Overview

```
                [Load Balancer]
                 (HAProxy/Nginx)
                       |
         +-------------+-------------+
         |             |             |
   [IAMShield 1]  [IAMShield 2]  [IAMShield 3]
         |             |             |
         +-------------+-------------+
                       |
              [PostgreSQL Primary]
                       |
              [PostgreSQL Replica]
```

### Minimum HA Requirements

| Component | Requirement |
|-----------|-------------|
| IAMShield Nodes | 3+ (clustered) |
| Load Balancer | 1+ (HAProxy, Nginx, AWS ALB) |
| Database | Primary + Replica (or cluster) |
| Network | Low latency between nodes |

### Clustering Configuration

**Node 1:**
```bash
bin/iamshield.sh start \
  --hostname=iam.yourdomain.com \
  --cache=ispn \
  --cache-stack=tcp \
  --db=postgres \
  --db-url=jdbc:postgresql://db-server:5432/iamshield
```

**Node 2 & 3:** (Same configuration)

IAMShield automatically discovers cluster members via JGroups/Infinispan.

### Load Balancer Configuration

**HAProxy Example** (`/etc/haproxy/haproxy.cfg`):

```haproxy
frontend iamshield_frontend
    bind *:443 ssl crt /etc/ssl/certs/iamshield.pem
    mode http
    default_backend iamshield_backend

backend iamshield_backend
    mode http
    balance roundrobin
    option httpchk GET /health/ready
    http-check expect status 200

    server iamshield1 10.0.1.10:8080 check inter 2000 rise 2 fall 3
    server iamshield2 10.0.1.11:8080 check inter 2000 rise 2 fall 3
    server iamshield3 10.0.1.12:8080 check inter 2000 rise 2 fall 3
```

### Database High Availability

**PostgreSQL Streaming Replication:**

**Primary Server:**
```bash
# postgresql.conf
wal_level = replica
max_wal_senders = 10
archive_mode = on
```

**Replica Server:**
```bash
# Create replica
pg_basebackup -h primary-host -D /var/lib/postgresql/data -U replicator -P --wal-method=stream
```

**Connection Pooling** (using PgBouncer - recommended):
```ini
[databases]
iamshield = host=postgres-primary port=5432 dbname=iamshield

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = 6432
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 30
```

---

## Security Considerations

### 1. Change Default Credentials

```bash
# Set admin password during first start
bin/iamshield.sh start --hostname=... \
  --initial-admin-username=admin \
  --initial-admin-password='StrongPassword123!'
```

### 2. Firewall Configuration

**Allow only required ports:**

```bash
# UFW (Ubuntu)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # HTTP (if needed)
sudo ufw allow from 10.0.1.0/24 to any port 9000  # Metrics (internal only)
sudo ufw enable

# Firewalld (RHEL)
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

### 3. Database Security

- Use strong passwords (16+ characters)
- Enable SSL for database connections
- Restrict database access to IAMShield servers only
- Regular backups with encryption

```bash
# PostgreSQL SSL
# postgresql.conf
ssl = on
ssl_cert_file = '/etc/ssl/certs/server-cert.pem'
ssl_key_file = '/etc/ssl/private/server-key.pem'
```

### 4. Regular Updates

```bash
# Check for updates
# Subscribe to security mailing list
# Plan update windows

# Backup before update
pg_dump iamshield > backup-$(date +%Y%m%d).sql

# Update
tar -xzf iamshield-new-version.tar.gz
# Migrate configuration
# Test in staging first
# Deploy to production
```

### 5. HTTPS Only

**Force HTTPS:**
```bash
bin/iamshield.sh start \
  --hostname=iam.yourdomain.com \
  --hostname-strict=true \
  --hostname-strict-https=true
```

### 6. Security Headers

Already configured by default:
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Content-Security-Policy
- Strict-Transport-Security (when HTTPS enabled)

---

## Monitoring & Maintenance

### Health Checks

```bash
# Health check endpoint
curl http://localhost:8080/health

# Ready check
curl http://localhost:8080/health/ready

# Live check
curl http://localhost:8080/health/live
```

### Metrics

Enable metrics:
```bash
bin/iamshield.sh start --metrics-enabled=true
```

Access metrics:
```bash
curl http://localhost:9000/metrics
```

**Prometheus Configuration** (`prometheus.yml`):
```yaml
scrape_configs:
  - job_name: 'iamshield'
    static_configs:
      - targets: ['iamshield-1:9000', 'iamshield-2:9000', 'iamshield-3:9000']
```

### Backup Strategy

**Database Backup:**
```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backup/iamshield"
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -h localhost -U iamshield iamshield | gzip > $BACKUP_DIR/iamshield_$DATE.sql.gz

# Keep backups for 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

**Configuration Backup:**
```bash
# Backup configuration files
tar -czf iamshield-config-$(date +%Y%m%d).tar.gz \
  /opt/iamshield/conf/ \
  /opt/iamshield/providers/ \
  /opt/iamshield/themes/
```

### Log Rotation

Create `/etc/logrotate.d/iamshield`:
```
/opt/iamshield/data/log/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 iamshield iamshield
    sharedscripts
    postrotate
        systemctl reload iamshield
    endscript
}
```

---

## Troubleshooting

### Common Issues

#### 1. Server Won't Start

**Check logs:**
```bash
tail -f data/log/iamshield.log
```

**Common causes:**
- Port 8080/8443 already in use
- Database connection failed
- Invalid configuration
- Insufficient memory

**Solutions:**
```bash
# Check port usage
sudo netstat -tulpn | grep 8080

# Test database connection
psql -h localhost -U iamshield -d iamshield

# Increase memory
export JAVA_OPTS_KC_HEAP="-Xms2g -Xmx4g"
```

#### 2. Database Connection Issues

**Error:** `Connection refused` or `Timeout`

**Check:**
```bash
# Test database connectivity
psql -h db-host -U iamshield -d iamshield

# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify firewall
sudo ufw status
```

**Fix PostgreSQL connection:**
```bash
# Edit pg_hba.conf
sudo nano /etc/postgresql/15/main/pg_hba.conf

# Add line:
host    iamshield    iamshield    10.0.0.0/8    md5

# Edit postgresql.conf
sudo nano /etc/postgresql/15/main/postgresql.conf

# Change:
listen_addresses = '*'

# Restart
sudo systemctl restart postgresql
```

#### 3. Out of Memory Errors

**Symptoms:**
- `java.lang.OutOfMemoryError`
- Server crashes randomly
- Slow performance

**Solution:**
```bash
# Increase heap size
export JAVA_OPTS_KC_HEAP="-Xms4g -Xmx8g"

# Or in systemd service
Environment="JAVA_OPTS_KC_HEAP=-Xms4g -Xmx8g"
```

#### 4. SSL Certificate Issues

**Error:** `Certificate expired` or `Invalid certificate`

**Solution:**
```bash
# Renew Let's Encrypt
sudo certbot renew

# Restart IAMShield
sudo systemctl restart iamshield

# Check certificate expiry
openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -noout -dates
```

#### 5. Slow Performance

**Check:**
- Database queries (use `EXPLAIN ANALYZE`)
- Connection pool size
- JVM heap size
- CPU/Memory usage

**Solutions:**
```bash
# Increase database pool
export KC_DB_POOL_MAX_SIZE=50

# Enable performance logging
bin/iamshield.sh start --log-level=DEBUG,org.hibernate:INFO

# Monitor with metrics
curl http://localhost:9000/metrics | grep iamshield
```

#### 6. Session Issues in Cluster

**Error:** Users logged out randomly

**Cause:** Clock drift between nodes

**Solution:**
```bash
# Install NTP
sudo apt install ntp

# Sync time
sudo ntpdate -s time.nist.gov

# Enable NTP service
sudo systemctl enable ntp
sudo systemctl start ntp
```

### Getting Help

**Log Collection:**
```bash
# Collect logs for support
tar -czf iamshield-logs-$(date +%Y%m%d).tar.gz \
  data/log/ \
  /var/log/syslog \
  /var/log/postgresql/
```

**System Information:**
```bash
# Generate system report
cat << EOF > system-info.txt
Java Version: $(java -version 2>&1)
OS: $(uname -a)
Memory: $(free -h)
Disk: $(df -h)
Database: $(psql --version)
IAMShield Version: $(cat version.txt)
EOF
```

---

## Quick Reference Commands

### Start/Stop Commands

```bash
# Development mode
bin/iamshield.sh start-dev

# Production mode
bin/iamshield.sh start --hostname=iam.yourdomain.com

# With systemd
sudo systemctl start iamshield
sudo systemctl stop iamshield
sudo systemctl restart iamshield
sudo systemctl status iamshield
```

### Configuration Commands

```bash
# Build configuration
bin/iamshield.sh build --db=postgres

# Show configuration
bin/iamshield.sh show-config

# Export configuration
bin/iamshield.sh export --file=export.json

# Import configuration
bin/iamshield.sh import --file=export.json
```

### Maintenance Commands

```bash
# Database backup
pg_dump iamshield > backup.sql

# Check health
curl http://localhost:8080/health

# View metrics
curl http://localhost:9000/metrics

# View logs
tail -f data/log/iamshield.log
```

---

## Support & Resources

### Documentation
- API Documentation: http://localhost:8080/admin/master/console/
- Admin Console: http://localhost:8080/admin

---

## Appendix

### A. Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `KC_DB` | Database vendor | - |
| `KC_DB_URL` | Database JDBC URL | - |
| `KC_DB_USERNAME` | Database username | - |
| `KC_DB_PASSWORD` | Database password | - |
| `KC_HOSTNAME` | Server hostname | localhost |
| `KC_PROXY` | Proxy mode (edge/reencrypt/passthrough) | none |
| `KC_HTTP_ENABLED` | Enable HTTP | false |
| `KC_HTTP_PORT` | HTTP port | 8080 |
| `KC_HTTPS_PORT` | HTTPS port | 8443 |
| `JAVA_OPTS_KC_HEAP` | JVM heap settings | -Xms64m -Xmx512m |
| `KC_LOG_LEVEL` | Log level | INFO |

### B. Configuration File Reference

Location: `conf/iamshield.conf`

```properties
# Database
db=postgres
db-url=jdbc:postgresql://localhost:5432/iamshield
db-username=iamshield
db-password=change_me

# HTTP/HTTPS
hostname=iam.yourdomain.com
hostname-strict=true
hostname-strict-https=true
proxy=edge

# Database pool
db-pool-initial-size=30
db-pool-max-size=30
db-pool-min-size=30

# Logging
log-level=INFO
log=console,file

# Features
features=token-exchange,admin-fine-grained-authz

# Health & Metrics
health-enabled=true
metrics-enabled=true

# Cache
cache=ispn
cache-stack=tcp
```

### C. Port Reference

| Port | Service | Purpose |
|------|---------|---------|
| 8080 | HTTP | Development/Internal |
| 8443 | HTTPS | Production access |
| 9000 | Management | Metrics/Health |
| 7600 | JGroups | Cluster communication |
| 5432 | PostgreSQL | Database (example) |

### D. Performance Tuning Checklist

- [ ] JVM heap sized appropriately
- [ ] Database connection pool tuned
- [ ] Database indexes optimized
- [ ] HTTP compression enabled
- [ ] Static resources cached
- [ ] CDN for theme resources (if applicable)
- [ ] Database on SSD storage
- [ ] Network latency < 10ms (in cluster)
- [ ] Clock synchronization (NTP)
- [ ] Monitoring in place

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01 | Initial deployment guide |

---

**Document Version:** 1.0
**Last Updated:** January 2025
**Maintained By:** IAMShield Team
