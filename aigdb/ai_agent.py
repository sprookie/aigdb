from typing import Callable, List

from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import StructuredTool, tool
from pydantic import BaseModel, Field

from .config import get_llm
from .gdb_controller import GDBController


class LoadCoreInput(BaseModel):
    exe_path: str = Field(..., description="可执行文件路径")
    core_path: str = Field(..., description="core文件路径")


class RunGdbInput(BaseModel):
    command: str = Field(..., description="原生GDB命令，例如 bt、info threads 等")


class StackInput(BaseModel):
    thread_id: int = Field(..., description="线程ID")


# 进阶工具输入
class SelectThreadInput(BaseModel):
    thread_id: int = Field(..., description="要选择的线程ID")


class SelectFrameInput(BaseModel):
    level: int = Field(..., description="要选择的栈帧层级，0为当前帧")


class MemoryReadInput(BaseModel):
    addr: str = Field(..., description="内存地址表达式，如 0x7fff... 或 $sp")
    count: int = Field(16, description="读取数量，1-256")
    fmt: str = Field("bx", description="显示格式，如 bx/wx/gx")


class DisassembleInput(BaseModel):
    count: int = Field(32, description="反汇编条目数量，1-256")


def build_agent(gdb: GDBController, on_gdb_log: Callable[[str], None]) -> AgentExecutor:
    """构建LangChain智能体，将GDB操作包装为工具供模型调用。"""

    def _log_and_return(tag: str, text: str) -> str:
        on_gdb_log(f"[{tag}]\n{text}\n")
        return text

    def _ensure_loaded() -> str:
        # 若标记未加载，但已记录exe/core，尝试自动恢复
        if not gdb.loaded:
            if gdb.exe_path and gdb.core_path:
                restore_out = gdb.reapply_target()
                on_gdb_log(f"[restore]\n{restore_out}\n")
                if gdb.verify_loaded():
                    gdb.loaded = True
                    return ""
            return "尚未加载core。请先使用load_core工具加载可执行文件与core。"
        # 已标记加载，但可能因为某些命令导致上下文丢失，尝试恢复
        if not gdb.verify_loaded():
            restore_out = gdb.reapply_target()
            on_gdb_log(f"[restore]\n{restore_out}\n")
        return ""

    def _safe_call(tag: str, fn) -> str:
        try:
            out = fn()
            return _log_and_return(tag, out)
        except Exception as e:
            on_gdb_log(f"[error]\n{e}\n")
            return f"(error: {e})"

    # LangChain @tool 风格重构：每个工具以装饰器定义，自动生成Schema
    @tool("load_core", args_schema=LoadCoreInput)
    def tool_load_core(exe_path: str, core_path: str) -> str:
        """加载core文件与可执行文件。"""
        out = gdb.load_core(exe_path, core_path)
        return _log_and_return("load_core", out)

    @tool("run_gdb", args_schema=RunGdbInput)
    def tool_run_gdb(command: str) -> str:
        """运行原生GDB命令，自动阻断破坏性命令。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        cmd_norm = command.strip().lower()
        dangerous_prefixes = [
            "file", "core-file", "symbol-file", "exec-file",
            "target", "attach", "run", "quit",
        ]
        if any(cmd_norm.startswith(p) for p in dangerous_prefixes):
            on_gdb_log(f"[blocked]\n阻止执行可能破坏上下文的命令：{command}\n")
            return "命令已阻止：可能清空或改变当前可执行/核心文件上下文。请改用 info/print/bt/x 等查看类命令。"
        out = gdb.run_cli(command)
        return _log_and_return("gdb", out)

    @tool("backtrace", args_schema=StackInput)
    def tool_bt(thread_id: int) -> str:
        """查看指定线程调用栈。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        out = gdb.stack_list_frames(thread_id=thread_id)
        return _log_and_return("backtrace", out)

    @tool("list_locals")
    def tool_locals() -> str:
        """列出当前栈帧的局部变量。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        out = gdb.stack_list_locals(all_values=True)
        return _log_and_return("locals", out)

    @tool("select_thread", args_schema=SelectThreadInput)
    def tool_select_thread(thread_id: int) -> str:
        """选择线程上下文。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("select_thread", lambda: gdb.select_thread(thread_id))

    @tool("select_frame", args_schema=SelectFrameInput)
    def tool_select_frame(level: int) -> str:
        """选择栈帧层级。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("select_frame", lambda: gdb.select_frame(level))

    @tool("registers")
    def tool_registers() -> str:
        """查看当前寄存器状态。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("registers", gdb.get_registers)

    @tool("disassemble", args_schema=DisassembleInput)
    def tool_disassemble(count: int) -> str:
        """反汇编PC附近若干指令。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("disassemble", lambda: gdb.disassemble_current(count))

    @tool("memory_read", args_schema=MemoryReadInput)
    def tool_memory_read(addr: str, count: int, fmt: str) -> str:
        """读取指定地址的内存块。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("memory", lambda: gdb.memory_read(addr, count, fmt))

    @tool("info_files")
    def tool_info_files() -> str:
        """查看当前映射/符号文件信息。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("info_files", gdb.info_files)

    @tool("sharedlibs")
    def tool_sharedlibs() -> str:
        """查看已加载的共享库信息。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("sharedlibs", gdb.info_sharedlibrary)

    @tool("bt_full")
    def tool_bt_full() -> str:
        """查看完整调用栈（包含参数与局部信息）。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("bt_full", gdb.bt_full)

    @tool("info_args")
    def tool_info_args() -> str:
        """查看当前函数参数。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("info_args", gdb.info_args)

    @tool("info_locals")
    def tool_info_locals() -> str:
        """查看当前帧局部变量。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("info_locals", gdb.info_locals)

    @tool("thread_info")
    def tool_thread_info() -> str:
        """查看线程信息。"""
        msg = _ensure_loaded()
        if msg:
            return msg
        return _safe_call("thread_info", gdb.thread_info)

    # 使用装饰器生成的工具对象集合
    tools = [
        tool_load_core,
        tool_run_gdb,
        tool_bt,
        tool_locals,
        tool_select_thread,
        tool_select_frame,
        tool_registers,
        tool_disassemble,
        tool_memory_read,
        tool_info_files,
        tool_sharedlibs,
        tool_bt_full,
        tool_info_args,
        tool_info_locals,
        tool_thread_info,
    ]

    llm = get_llm()

    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一个资深Linux崩溃排查助手。你可以通过工具操作GDB收集信息，并基于证据做出推断与建议。\n"
                   "工作流：\n"
                   "1) 若未加载core，先使用load_core。\n"
                   "2) 先获取thread_info、bt/bt_full、signal与program状态；\n"
                   "3) 必要时select_thread/select_frame，查看registers、disassemble、memory_read；\n"
                   "4) 汇总发现与因果链，提出修复建议与定位方法。\n"
                   "规则：每次只调用一个最必要的工具；读完输出后再决定下一步；最终给出清晰结论、证据列表与建议。"),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    # 关闭verbose，避免将内部链路日志打印到stdout造成界面干扰；
    # 增加健壮性：限制迭代次数、处理解析错误，并返回中间步骤以便外层需要时记录。
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,
        max_iterations=12,
        handle_parsing_errors="工具解析失败，请重试或调整指令。",
        return_intermediate_steps=True,
    )