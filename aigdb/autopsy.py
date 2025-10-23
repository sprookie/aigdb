from typing import Callable

from .gdb_controller import GDBController


class AutoAnalyzer:
    """自动分析流程：采集关键信息并生成总结文本。
    注：分析报告的总结（归纳因果与建议）由AI在外层完成，这里侧重采样事实。
    """

    def __init__(self, gdb: GDBController, on_gdb_log: Callable[[str], None]):
        self.gdb = gdb
        self.on_gdb_log = on_gdb_log

    def _log(self, tag: str, text: str) -> str:
        self.on_gdb_log(f"[{tag}]\n{text}\n")
        return text

    def collect(self) -> str:
        chunks = []
        chunks.append(self._log("thread_info", self.gdb.thread_info()))
        chunks.append(self._log("signal", self.gdb.get_signal_summary()))
        # 采集主线程调用栈（尝试选择当前停止线程）
        chunks.append(self._log("bt", self.gdb.stack_list_frames(thread_id=None)))
        chunks.append(self._log("locals", self.gdb.stack_list_locals(all_values=True)))
        return "\n\n".join(chunks)