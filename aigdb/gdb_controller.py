from typing import List, Dict, Optional, Tuple
from pygdbmi.gdbcontroller import GdbController


class GDBController:
    """使用GDB/MI驱动gdb以实现可编程控制与输出采集。

    设计选择：
    - 使用`--interpreter=mi2`与`pygdbmi`交互，不启用gdb的TUI，以便在同一CLI窗口中自定义显示。
    - 提供常用操作封装：加载core、线程信息、调用栈、打印表达式等。
    """

    def __init__(self, gdb_path: str = "gdb") -> None:
        try:
            # 使用MI2以匹配当前实现与pygdbmi解析
            self._gdb = GdbController(command=[gdb_path, "--interpreter=mi2"])
        except TypeError:
            try:
                # 旧版本pygdbmi使用gdb_path参数
                self._gdb = GdbController(gdb_path=gdb_path)
            except TypeError:
                # 最后回退到默认构造
                self._gdb = GdbController()
        self.loaded: bool = False
        self.exe_path: Optional[str] = None
        self.core_path: Optional[str] = None

    # --- 基础MI交互 ---
    def write_mi(self, mi_cmd: str, timeout_sec: float = 5.0) -> List[Dict]:
        return self._gdb.write(mi_cmd, timeout_sec=timeout_sec)

    def write_cli(self, cli_cmd: str, timeout_sec: float = 5.0) -> List[Dict]:
        # 使用interpreter-exec运行原生CLI命令
        cmd = f'interpreter-exec console "{cli_cmd}"'
        return self.write_mi(cmd, timeout_sec)

    @staticmethod
    def format_responses(responses: List[Dict]) -> str:
        lines: List[str] = []
        for r in responses:
            # 提取payload或message
            payload = r.get("payload")
            msg = r.get("message")
            if isinstance(payload, dict):
                lines.append(str(payload))
            elif payload:
                lines.append(str(payload))
            elif msg:
                lines.append(str(msg))
        return "\n".join(lines) if lines else "(no output)"

    # --- 高层封装 ---
    def load_core(self, exe_path: str, core_path: str) -> str:
        self.exe_path = exe_path
        self.core_path = core_path
        out1 = self.write_mi(f"-file-exec-and-symbols {exe_path}")
        out2 = self.write_mi(f"-target-select core {core_path}")
        # 根据当前状态校验是否加载成功
        self.loaded = self.verify_loaded()
        return self.format_responses(out1 + out2)

    def thread_info(self) -> str:
        res = self.write_mi("-thread-info")
        return self.format_responses(res)

    def stack_list_frames(self, thread_id: Optional[int] = None) -> str:
        # 选择线程后列出栈帧
        outputs: List[Dict] = []
        if thread_id is not None:
            outputs += self.write_mi(f"-thread-select {thread_id}")
        outputs += self.write_mi("-stack-list-frames")
        return self.format_responses(outputs)

    def stack_list_locals(self, all_values: bool = True) -> str:
        flag = "--all-values" if all_values else "--no-values"
        res = self.write_mi(f"-stack-list-variables {flag}")
        return self.format_responses(res)

    def print_expr(self, expr: str) -> str:
        res = self.write_cli(f"print {expr}")
        return self.format_responses(res)

    def run_cli(self, cmd: str) -> str:
        res = self.write_cli(cmd)
        return self.format_responses(res)

    def get_signal_summary(self) -> str:
        # 尝试通过CLI获取信号与停止原因
        res = self.write_cli("info signal") + self.write_cli("info program")
        return self.format_responses(res)

    def quit(self) -> None:
        try:
            self.write_mi("-gdb-exit")
        except Exception:
            pass
    # --- 进阶分析能力 ---
    def select_thread(self, thread_id: int) -> str:
        res = self.write_mi(f"-thread-select {thread_id}")
        return self.format_responses(res)

    def select_frame(self, level: int) -> str:
        # 选择指定栈帧层级（0为最顶层当前帧）
        res = self.write_mi(f"-stack-select-frame {level}")
        return self.format_responses(res)

    def get_registers(self) -> str:
        res = self.write_cli("info registers")
        return self.format_responses(res)

    def disassemble_current(self, count: int = 32) -> str:
        # 在PC附近反汇编
        count = max(1, min(count, 256))
        res = self.write_cli(f"x/{count}i $pc")
        return self.format_responses(res)

    def memory_read(self, addr: str, count: int = 16, fmt: str = "bx") -> str:
        # 使用x命令读取内存：fmt例如 bx(字节十六进制)、wx(字)、gx(双字)
        count = max(1, min(count, 256))
        fmt = fmt.strip()
        res = self.write_cli(f"x/{count}{fmt} {addr}")
        return self.format_responses(res)

    def info_files(self) -> str:
        res = self.write_cli("info files")
        return self.format_responses(res)

    def info_sharedlibrary(self) -> str:
        res = self.write_cli("info sharedlibrary")
        return self.format_responses(res)

    def bt_full(self) -> str:
        res = self.write_cli("bt full")
        return self.format_responses(res)

    def info_args(self) -> str:
        res = self.write_cli("info args")
        return self.format_responses(res)

    def info_locals(self) -> str:
        res = self.write_cli("info locals")
        return self.format_responses(res)

    # --- 状态校验与恢复 ---
    def verify_loaded(self) -> bool:
        """粗略校验是否仍处于已加载的core上下文。
        依据：`info files`输出中若包含“No executable file now.”或“No symbol file now.”则视为未加载。
        只做轻量启发式检查，避免引入复杂解析。
        """
        try:
            out = self.run_cli("info files")
        except Exception:
            return False
        txt = out.strip().lower()
        if "no executable file now" in txt or "no symbol file now" in txt:
            return False
        return True

    def reapply_target(self) -> str:
        """在已记录exe/core的前提下，重新应用到当前会话。返回GDB的输出。"""
        if not self.exe_path or not self.core_path:
            return "(no recorded exe/core to reapply)"
        out1 = self.write_mi(f"-file-exec-and-symbols {self.exe_path}")
        out2 = self.write_mi(f"-target-select core {self.core_path}")
        # 重新校验真实加载状态
        self.loaded = self.verify_loaded()
        return self.format_responses(out1 + out2)