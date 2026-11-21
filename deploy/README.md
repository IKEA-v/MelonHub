# MelonHub Docker Swarm 部署

该 Stack 使用已有的 `javaee-proxy` overlay 网络，连接已有 MySQL Swarm 服务名 `mysql`，并创建 MelonHub 自己的后端和前端服务。联调阶段关闭 Redis 权限缓存，权限直接由 MySQL 校验。

## 构建镜像

在项目根目录完成构建：

```powershell
mvn -f backend/pom.xml -DskipTests package
npm --prefix frontend run build
```

然后在可访问镜像仓库的 Docker 主机上构建并推送：

```bash
docker build -t "$BACKEND_IMAGE" backend
docker push "$BACKEND_IMAGE"
docker build -t "$FRONTEND_IMAGE" frontend
docker push "$FRONTEND_IMAGE"
```

## 部署

复制 `env.example` 为部署主机上的 `.env`，填入数据库、管理员、JWT 和 CORS 配置。密码和 JWT 密钥不能提交到仓库。

确认 `javaee-proxy` 已存在，并在 Docker Swarm 管理节点执行：

```bash
docker network inspect javaee-proxy >/dev/null 2>&1 || docker network create --driver overlay --attachable javaee-proxy
set -a
. deploy/.env
set +a
docker stack deploy --with-registry-auth --prune -c deploy/stack.yml melonhub
```

部署后检查：

```bash
docker stack services melonhub
curl -fsS http://127.0.0.1:18081/actuator/health
curl -fsS http://127.0.0.1:18080/auth/me
```

`/auth/me` 未携带令牌时应返回 401。课程系统的 `IDENTITY_BASE_URL` 和前端 `VITE_IDENTITY_BASE_URL` 指向 `http://<服务器IP>:18080`，再执行 MelonHub 根目录的 `scripts/setup-course-integration.ps1`。

## 日志

```bash
docker service logs -f melonhub_melonhub-backend
docker service logs -f melonhub_melonhub-frontend
docker service logs -f melonhub_melonhub-redis
```

课程前端如果通过浏览器直接调用 `/auth/*`，必须把其 Origin 加到 `CORS_ALLOWED_ORIGINS`。数据库连接只使用 `mysql` Swarm 服务名和 `melonhub_rbac` 库，不创建或修改其他应用数据库。`CACHE_ENABLED=false` 时不需要 Redis 服务。
