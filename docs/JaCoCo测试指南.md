# JaCoCo 测试指南

更新日期：2026-10-29。JaCoCo 随后端测试记录 Java 代码执行情况，生成行、分支等覆盖率。它不会测试已部署的服务器容器，也不包含前端或独立 Java SDK。

## 准备

在项目根目录打开 PowerShell，使用 JDK 21 和 Maven。当前电脑 JDK 为 `D:/jdk21`，其他电脑按实际位置设置。忽略的 `.env` 需要填写 `CLOUD_DB_*`、`TEST_DB_URL/TEST_DB_USERNAME/TEST_DB_PASSWORD`。

测试只能使用云端独立库 `melonhub_rbac_test`，不能连接正式库。测试会写入测试数据并执行迁移，不要与别人共用同一个测试库并发运行。`BACKEND_MODE=server` 不影响测试目标，测试在本机专用进程运行。

## 完整命令

```powershell
$env:JAVA_HOME = 'D:/jdk21'
$env:SPRING_DATASOURCE_HIKARI_MAX_LIFETIME = '60000'
$env:SPRING_DATASOURCE_HIKARI_KEEPALIVE_TIME = '30000'
$env:SPRING_TRANSACTION_DEFAULT_TIMEOUT = '120s'
./scripts/test-backend.ps1 -Coverage
```

三个 Spring 参数只作用于当前终端启动的测试进程，用于云连接回收和较长集成事务，不修改服务器配置。结束后关闭该终端即可；不要继续在同一终端启动本机正式后端并误用这些参数。

脚本执行 `clean verify -Pcoverage`：清理旧产物、挂载 agent、编译执行全部后端测试、打包并生成报告。当前 JaCoCo 0.8.12，本次使用 JDK 21，没有最低覆盖率门槛。

耗时取决于用例数量和云数据库网络，等待 `BUILD SUCCESS` 才表示完整执行成功。出现 `BUILD FAILURE` 时应排查错误，不能用旧报告声称这次通过。

## 打开与理解报告

```powershell
Start-Process ./backend/target/site/jacoco/index.html
```

可逐层进入包、类和源码。红色表示未覆盖，黄色表示部分分支覆盖，绿色表示覆盖；重点关注鉴权、授权和事务等关键路径，而非只看汇总百分比。

| 文件 | 用途 |
| --- | --- |
| `backend/target/site/jacoco/index.html` | 浏览器报告入口 |
| `backend/target/site/jacoco/jacoco.xml` | CI 或分析工具输入 |
| `backend/target/site/jacoco/jacoco.csv` | 汇总统计 |
| `backend/target/surefire-reports/` | 各组测试结果及失败明细 |

报告是忽略的构建产物，下一次 `clean` 会删除。需要交作业时可把整个 `backend/target/site/jacoco/` 目录另存到提交材料目录；单独一个 HTML 文件缺少样式及子页面。

## Controller 接口测试

`backend/src/test/java/com/melonhub/rbac/ControllerIntegrationTest.java` 新增 13 项执行用例（含两种业务路由的参数化测试），通过 MockMvc 进入真实过滤器、Controller、Service 和 DAO。测试数据、临时管理员、会话及业务密钥只在云测试库创建，并随测试事务回滚；不访问正式库，不发送真实外部 Webhook。

| 测试流程 | 关键断言 |
| --- | --- |
| 申请批准、拒绝和取消 | 状态变化、授权仅在批准后生效、重复批准冲突、只读管理员及跨软件审批拒绝 |
| 复核 | 快照分页、非法决定拒绝、关闭后才回收授权、重复关闭冲突、跨软件读取拒绝 |
| Webhook | 新建、编辑、删除、测试事件进入待发送队列、停用后拒绝测试、列表不暴露密钥 |
| 清单与用户导入 | v3 导出再导入、旧版拒绝、用户新增与重复导入更新、平台写权限检查 |
| 报表与系统状态 | 可见软件过滤、到期天数边界、权限持有人、搜索、健康字段、审计校验入口、限流配置 |
| 业务角色与上下文 | 软件路由及部门兼容路由、权限关联、整体替换/清空角色、停用角色、其他软件密钥拒绝修改、上下文撤销 |
| 管理配置 | 部门/软件/用户增删改、密钥轮换使旧密钥失效、角色成员、权限诊断、批量授权、分页边界和非法请求 |

行覆盖率只说明代码执行过，分支覆盖率也不能证明所有角色、输入和并发组合均已验证。仅在过滤器被拒绝的 401 请求可能不会执行 Controller；因此新增用例同时检查合法调用和授权拒绝，并通过后续读取验证写入结果。新增用例关闭 MockMvc 自动打印请求和响应，避免把临时凭据输出到日志。

只补测试和文档时无需重新部署服务器。若测试发现并修复了生产代码问题，则应先完成回归，再按服务器部署指南更新运行包。

## 本次结果

2026-10-29 补充 Controller 测试后完整执行 `clean verify -Pcoverage`，耗时 9 分 32 秒，`BUILD SUCCESS`：147 项，140 项通过、7 项跳过、0 失败、0 错误。行覆盖率 88.84%，分支 69.97%，指令 81.82%，方法 88.49%，类 92.86%。

| 范围 | 补测前行覆盖率 | 补测后行覆盖率 |
| --- | --- | --- |
| 后端整体 | 80.36% | 88.84%（2212/2490 行） |
| Controller 包 | 29.28% | 94.48%（171/181 行） |
| GovernanceController | 6.78% | 100.00%（59/59 行） |
| BusinessController | 31.71% | 100.00%（41/41 行） |
| AdminController | 29.41% | 98.04%（50/51 行） |
| AuthController | 64.29% | 64.29%（9/14 行） |
| AccountController | 75.00% | 75.00%（12/16 行） |

Controller 分支覆盖为 88.89%（16/18），其中治理 Controller 的 12 个分支均执行。100% 行覆盖不代表所有权限组合或业务场景均已验证；认证和账号 Controller 仍有未覆盖路径，后续可继续补测。

本轮报告备份为 `output/verification-20261029-controller/jacoco/index.html`，完整测试明细位于该目录的 `surefire-reports/`；补测前报告保留在 `output/verification-20261029/jacoco/`。这些目录均为本机忽略产物，Gitee 保存测试源码和验证记录。

Redis 关闭导致权限缓存集成 6 项、治理中的 Redis 全局限流 1 项跳过，不能理解为缓存已验证。覆盖这些路径需要先配置专用测试 Redis 再重跑，不得连接其他应用的 Redis。

只跑普通后端测试、不生成覆盖率时执行 `./scripts/test-backend.ps1`。若发生网络超时，恢复云测试库连接后重跑完整覆盖率；不要绕过数据库目标保护，也不要用正式库替代。
