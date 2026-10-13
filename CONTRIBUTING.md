# 贡献指南

感谢你对本项目的关注！以下是参与贡献的规范。

## 开发环境

- Python 3.10+
- 推荐使用虚拟环境：`python -m venv .venv && .venv\Scripts\activate`
- 安装依赖：`pip install -r requirements.txt`

## 提交规范

提交信息遵循以下格式：

```
<type>(<scope>): <subject>

<body>
```

**type 类型：**
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `refactor`: 代码重构（不改变功能）
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具/依赖变更

**示例：**
```
feat(scan): 新增 SQL 注入检测模块
fix(guard): 修复内网 IP 校验绕过
docs(readme): 更新安装说明
```

## 代码规范

- Python：遵循 PEP 8，使用 4 空格缩进
- 函数和类必须有 docstring
- 关键逻辑必须有注释说明
- 不提交硬编码的密钥、IP、路径（使用配置文件或环境变量）

## 安全规范

本项目涉及网络安全工具，贡献时必须遵守：

1. **仅用于授权测试**：所有代码必须在授权范围内使用
2. **不包含破坏性 payload**：PoC 代码必须是非破坏性的
3. **隐私保护**：不提交包含真实 IP、域名、凭据的测试数据
4. **护栏优先**：新增功能必须集成 guard.py 的目标校验

## 提交流程

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feat/your-feature`
3. 提交更改：`git commit -m 'feat: 描述'`
4. 推送分支：`git push origin feat/your-feature`
5. 提交 Pull Request

## 报告问题

提交 Issue 时请包含：
- 操作系统和 Python 版本
- 复现步骤
- 期望行为 vs 实际行为
- 错误日志或截图

## 许可证

提交代码即表示你同意该代码以 MIT 许可证发布。
