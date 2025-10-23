# AIGDB: LangChain驱动的Linux core文件自动分析助手

AIGDB是一个在终端内运行的AI助手，基于LangChain 1.x 与 GDB的MI接口，支持：
- 加载Linux核心转储（core）与对应的可执行文件
- AI自动发起GDB命令，采集关键信息（线程、调用栈、寄存器、信号等）
- 在同一个CLI窗口中并行显示：AI对话与GDB输出日志
- 一键自动分析core并生成总结报告

> 注意：运行分析需要在Linux或WSL环境下安装`gdb`。本仓库可在Windows开发，但运行时请确保有Linux/WSL。

## 安装

```bash
pip install -r requirements.txt
```

配置DeepSeek（OpenAI兼容）API：在`.env`文件中设置：

```env
OPENAI_API_KEY=你的deepseek_key
OPENAI_BASE_URL=https://api.deepseek.com/v1
OPENAI_MODEL=deepseek-chat
```

默认已在代码中切换到 DeepSeek（`deepseek-chat`），你也可以使用其他兼容模型。

## 快速开始

```bash
python -m aigdb.cli
```

启动后在底部输入框可使用以下命令：
- 普通自然语言提问：例如“我的core文件目录在<目录>，造成崩溃的二进制文件在<目录>，帮我分析一下”
- `/load /path/to/exe /path/to/core` 载入可执行与core
- `/collect` 收集基本信息给ai，让ai生成基本的汇总报告
- `/analyze` 自动分析core并生成报告
- `/cmd <gdb命令>` 直接运行原生GDB命令（如`bt`, `info threads`等）

## 技术架构概览

- GDB控制：使用`pygdbmi`与`--interpreter=mi2`驱动GDB，可编程、可并行采集输出
- AI层：基于LangChain Tool-Calling Agent，将GDB操作包装为工具，由模型调用（默认DeepSeek）
- CLI交互：`prompt_toolkit`构建分栏TUI（左侧GDB日志，右侧AI对话），底部输入
- 自动分析：执行一系列MI命令收集上下文并由LLM生成结论与建议


## 目录结构

```
aigdb/
  cli.py        # 交互式CLI入口
  gdb_controller.py  # GDB MI控制器
  ai_agent.py   # LangChain智能体与工具
  autopsy.py    # 自动分析流程
  config.py     # 配置与环境变量（默认DeepSeek）
```

## 运行环境建议
- Linux或WSL，安装`gdb`，并能访问core与对应的二进制文件
- Python 3.10+
