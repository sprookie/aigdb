import asyncio
from typing import List

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit, VSplit, Window
from prompt_toolkit.layout.controls import BufferControl
from prompt_toolkit.styles import Style
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from .gdb_controller import GDBController
from .ai_agent import build_agent
from .autopsy import AutoAnalyzer
from prompt_toolkit.widgets import Frame
from datetime import datetime
import textwrap


class CLIApp:
    def __init__(self) -> None:
        self.gdb = GDBController()
        self.gdb_log: List[str] = []
        self.ai_log: List[str] = []

        def on_gdb_log(text: str) -> None:
            self.gdb_log.append(text)
            self.refresh_views()

        self.agent = build_agent(self.gdb, on_gdb_log)
        self.autopsy = AutoAnalyzer(self.gdb, on_gdb_log)

        # 输入缓冲区：单行，按 Enter 发送
        self.input_buffer = Buffer(multiline=False)
        self.gdb_buffer = Buffer(read_only=True)
        self.ai_buffer = Buffer(read_only=True)

        # 键盘绑定：退出与焦点切换
        self.kb = KeyBindings()
        @self.kb.add('c-c')
        def _(event):
            event.app.exit()
        @self.kb.add('c-q')
        def _(event):
            event.app.exit()
        @self.kb.add('q')
        def _(event):
            buf = event.app.current_buffer
            if buf is self.input_buffer and buf.text.strip():
                return
            event.app.exit()
        @self.kb.add('enter')
        def _(event):
            # 按 Enter 发送当前输入到 AI/命令分派
            event.current_buffer.validate_and_handle()
        @self.kb.add('tab')
        def _(event):
            event.app.layout.focus(self.input_buffer)
        @self.kb.add('f6')
        def _(event):
            event.app.layout.focus(self.gdb_buffer)
        @self.kb.add('f7')
        def _(event):
            event.app.layout.focus(self.ai_buffer)

        # 初始欢迎提示，避免界面空白，并提示操作指南
        self.gdb_log.append("[GDB]\n欢迎使用 AIGDB · 左侧显示 GDB 日志")
        self.ai_log.append(
            "[AI]\n提示：\n"
            "- Tab 聚焦底部输入；F6/F7 切换左右面板\n"
            "- Ctrl+C 或 q 退出\n"
            "- /load <exe> <core> 加载core\n"
            "- /cmd <gdb命令> 运行原生GDB命令\n"
            "- /analyze 或 /analyse 启动AI分步自动分析\n"
            "- /collect 采样关键信息并汇总\n"
        )

        root_container = HSplit([
            VSplit([
                Frame(Window(content=BufferControl(buffer=self.gdb_buffer), width=80, wrap_lines=True), title='GDB'),
                Frame(Window(content=BufferControl(buffer=self.ai_buffer), wrap_lines=True), title='AI'),
            ]),
            Window(height=1, char='─'),
            Window(content=BufferControl(buffer=self.input_buffer)),
        ])

        self.style = Style.from_dict({
            "window.border": "bg:#444444",
        })

        self.app = Application(
            layout=Layout(root_container),
            style=self.style,
            full_screen=True,
            after_render=self.refresh_views,
            key_bindings=self.kb,
            mouse_support=True,
        )

        # 绑定回车处理输入
        self.input_buffer.accept_handler = self.on_enter

    def refresh_views(self, *_) -> None:
        self.gdb_buffer.set_document(Document("\n".join(self.gdb_log[-400:])), bypass_readonly=True)
        self.ai_buffer.set_document(Document("\n".join(self.ai_log[-400:])), bypass_readonly=True)
        # 默认保持输入行聚焦，确保键入有响应
        try:
            self.app.layout.focus(self.input_buffer)
        except Exception:
            pass

    async def handle_user_text(self, text: str) -> None:
        text = text.strip()
        if not text:
            return
        # 命令分派
        if text.startswith("/load "):
            try:
                _, exe, core = text.split(maxsplit=2)
                out = self.gdb.load_core(exe, core)
                self.gdb_log.append(f"[load_core]\n{out}\n")
            except Exception as e:
                self.ai_log.append(self.format_ai_text(f"载入失败：{e}"))
        elif text.startswith("/cmd "):
            cmd = text[len("/cmd ") :]
            out = self.gdb.run_cli(cmd)
            self.gdb_log.append(f"[GDB {datetime.now().strftime('%H:%M:%S')}]\n{out}\n")
        elif text.strip() == "/analyze":
            # 让AI按工作流自行调用工具，分步分析
            # 预检是否已加载上下文，未加载则提示并返回
            if not self.gdb.verify_loaded():
                self.ai_log.append(self.format_ai_text("尚未加载core，请先使用 /load <exe> <core> 进行加载。"))
                self.refresh_views()
                return
            # 提供当前上下文与状态，减少模型误判再去调用load_core
            info = self.gdb.info_files()
            self.gdb_log.append(f"[info_files {datetime.now().strftime('%H:%M:%S')}]\n{info}\n")
            self.ai_log.append(self.format_ai_text("开始自动分析，请稍候…"))
            result = await self.agent.ainvoke({
                "input": (
                    f"上下文已加载：exe_path={self.gdb.exe_path}, core_path={self.gdb.core_path}。"\
                    "你应先调用 thread_info 与 bt/bt_full 验证上下文，然后根据需要 select_thread/select_frame、registers、disassemble、memory_read。"\
                    "不要再次调用 load_core 或任何会更改目标的命令。现在开始分析。"
                ),
            })
            self.ai_log.append(self.format_ai_text(str(result.get("output", "(no output)"))))
        elif text.strip() == "/analyse":
            # 英式拼写兼容，同步触发分步分析
            # 预检是否已加载上下文，未加载则提示并返回
            if not self.gdb.verify_loaded():
                self.ai_log.append(self.format_ai_text("尚未加载core，请先使用 /load <exe> <core> 进行加载。"))
                self.refresh_views()
                return
            # 提供当前上下文与状态，减少模型误判再去调用load_core
            info = self.gdb.info_files()
            self.gdb_log.append(f"[info_files {datetime.now().strftime('%H:%M:%S')}]\n{info}\n")
            self.ai_log.append(self.format_ai_text("开始自动分析，请稍候…"))
            result = await self.agent.ainvoke({
                "input": (
                    f"上下文已加载：exe_path={self.gdb.exe_path}, core_path={self.gdb.core_path}。"\
                    "你应先调用 thread_info 与 bt/bt_full 验证上下文，然后根据需要 select_thread/select_frame、registers、disassemble、memory_read。"\
                    "不要再次调用 load_core 或任何会更改目标的命令。现在开始分析。"
                ),
            })
            self.ai_log.append(self.format_ai_text(str(result.get("output", "(no output)"))))

        elif text.strip() == "/collect":
            collected = self.autopsy.collect()
            self.ai_log.append(self.format_ai_text("采样完成，正在汇总…"))
            result = await self.agent.ainvoke({
                "input": f"以下是采集到的关键信息，请根据证据进行总结与建议：\n\n{collected}",
            })
            self.ai_log.append(self.format_ai_text(str(result.get("output", "(no output)"))))
        else:
            # 普通自然语言交互
            result = await self.agent.ainvoke({"input": text})
            self.ai_log.append(self.format_ai_text(str(result["output"])))
        self.refresh_views()

    def format_ai_text(self, text: str) -> str:
        ts = datetime.now().strftime('%H:%M:%S')
        text = text.strip()
        # 轻度规整：去除长空行、统一换行
        lines = [l.rstrip() for l in text.splitlines()]
        if not lines:
            return f"[AI {ts}]\n(no output)\n"
        # 保持原始内容，但增加分隔与时间戳
        body = "\n".join(lines)
        return f"[AI {ts}]\n{body}\n\n"  

    def on_enter(self, buf: Buffer) -> bool:
        text = buf.text
        buf.text = ""
        asyncio.ensure_future(self.handle_user_text(text))
        return True


def main() -> None:
    app = CLIApp()
    app.app.run()


if __name__ == "__main__":
    main()