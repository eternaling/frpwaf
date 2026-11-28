#!/usr/bin/env python3
# coding: utf-8
"""两端面板（插件端 `index.html` / Web 端 `web/index.html`）概览口径一致性测试。

为什么要断言 HTML 文案：概览卡片的主值含义变了（「日志窗口连接」→「近24h连接 + 真累计」、
「黑名单」→「近24h新增封禁」、内核丢弃加「近 1 分钟」速率副行），而两端是**两份独立
的原生 JS 单文件**，没有共享模板。只改一端就会出现「插件端说 24 小时、网页端说窗口」
这种口径漂移，且不会报错、只能靠人眼看出来。这里用最朴素的方式钉住：
两端都必须出现同一批关键文案与字段名。

同时反向断言：旧文案不能残留（「日志窗口连接」这个词一旦还在卡片上，
说明有一端没改完）。
"""
import os
import unittest

from . import new_home  # noqa: F401  —— 只为统一夹层（改 FRPWAF_HOME），本文件不碰数据

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.join(ROOT, "index.html")
WEB = os.path.join(ROOT, "web", "index.html")


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class PanelFieldsTest(unittest.TestCase):
    """两端都必须读新字段。"""

    @classmethod
    def setUpClass(cls):
        cls.panel = _read(PANEL)
        cls.web = _read(WEB)

    def test_both_read_new_overview_fields(self):
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            for field in ("conns_24h", "conns_total", "bans_24h",
                          "kern_drop_rate", "kern_drop_mode"):
                self.assertIn(field, text, "%s 缺少字段 %s" % (name, field))

    def test_legacy_field_is_not_a_card_anymore(self):
        """`total_conns` 仍可从接口读到，但不该再当卡片主值展示。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertNotIn("'日志窗口连接'", text, name)
            self.assertNotIn("d.total_conns, ''", text, name)


class PanelCopyTest(unittest.TestCase):
    """两端关键文案必须一字不差地一致（除非另一端没有这个区块）。"""

    @classmethod
    def setUpClass(cls):
        cls.panel = _read(PANEL)
        cls.web = _read(WEB)

    def test_card_titles_present_in_both(self):
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            for title in ("近24h连接", "真累计", "近24h新增封禁", "内核层已丢弃",
                          "生效封禁"):
                self.assertIn(title, text, "%s 缺少卡片文案 %s" % (name, title))

    def test_rate_copy_present_in_both(self):
        """「近 1 分钟 X 包/秒」的文案与「未知显示 —」的约定两端一致。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("近 1 分钟", text, name)
            self.assertIn("包/秒", text, name)

    def test_caliber_note_mentions_rejected_and_trim(self):
        """口径说明必须写清：主值是 24 小时、真累计含被拒绝且不受裁剪影响。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("滑动窗口", text, name)
            self.assertIn("含被拒绝的连接", text, name)
            self.assertIn("不受日志裁剪影响", text, name)
            self.assertIn("删旧日志不会让它变小", text, name)

    def test_black_count_is_demoted_to_subline(self):
        """累计名单数仍在（副行），但不再是卡片主值。

        注意不能粗暴断言「文件里没有 黑名单」：运行信息区块里还有一个
        「黑名单 已启用/关闭」的开关状态展示，那个必须保留。
        """
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("永久名单", text, name)
            self.assertNotIn("['黑名单', d.black_count", text, name)


class PanelKernbanTopTest(unittest.TestCase):
    """内核封禁页的来源 Top 折叠展示：两端都要有，且三态文案齐备。"""

    @classmethod
    def setUpClass(cls):
        cls.panel = _read(PANEL)
        cls.web = _read(WEB)

    def test_top_rendering_present_in_both(self):
        self.assertIn("fwKernTop", self.panel)
        self.assertIn("renderKbTop", self.web)
        self.assertIn("kbTop", self.web)
        # 两端都要能表达「计数未启用」这一态
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("尚未启用", text, name)


class PanelStatsLayoutTest(unittest.TestCase):
    """概览卡片区的布局契约：卡片在网格里，说明文字在网格外。

    背景：插件端曾把「统计口径」与「攻击类型封禁」两段说明直接拼进
    `<div class="fw-stats" id="fwStats">` 的 innerHTML，还给它挂了
    `flex-basis:100%`——`flex-basis` 是 flex 属性，在 grid 容器里**完全无效**，
    于是说明被当成一个普通网格单元格，挤进 auto-fit 的窄列里逐字竖排，
    并把同一行卡片撑高。本类用纯文本断言钉住「说明不在网格内」这条结构契约。
    """

    STATS_MARKER = '<div class="fw-stats" id="fwStats"></div>'
    NOTE_ID = 'id="fwStatsNote"'

    @classmethod
    def setUpClass(cls):
        cls.panel = _read(PANEL)
        cls.web = _read(WEB)

    def test_flex_basis_hack_is_gone_from_both_panels(self):
        """两端都不该再出现 flex-basis（它在 grid 容器里不生效，只是障眼法）。"""
        """两端都不能再用内联 style="flex-basis:100%" 凑整宽。

        断言的是真正的 bug 签名（内联样式声明本身）；注释里提到这个失效属性
        是允许的（那是在解释为什么不能这么写），所以不断言裸词。
        """
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertNotIn('style="flex-basis', text,
                             "%s 仍有内联 flex-basis（grid 容器里无效，说明会被挤成竖列）" % name)
            self.assertNotIn("100%;margin:6px 0 0", text,
                             "%s 的说明文字仍靠 flex-basis:100%% 凑整宽" % name)

    def test_note_container_sits_outside_the_card_grid(self):
        """说明容器 `#fwStatsNote` 必须是 `#fwStats` 的后续兄弟节点，不是其子节点。"""
        self.assertIn(self.STATS_MARKER, self.panel)
        self.assertIn(self.NOTE_ID, self.panel)
        # `#fwStats` 写成空的自闭合容器，说明容器出现在它之后 → 两者是兄弟而非嵌套
        self.assertGreater(self.panel.index(self.NOTE_ID),
                           self.panel.index(self.STATS_MARKER),
                           "#fwStatsNote 必须排在 #fwStats 之后（网格之外）")
        # 网格容器仍保留，卡片继续走 auto-fit 响应式
        self.assertIn("repeat(auto-fit,minmax(170px,1fr))", self.panel)

    def test_card_grid_inner_html_holds_only_cards(self):
        """写进 `#fwStats` 的 innerHTML 里不能再夹带任何 .fw-tip 说明。"""
        start = self.panel.index("document.getElementById('fwStats').innerHTML")
        end = self.panel.index("document.getElementById('fwStatsNote').innerHTML")
        self.assertGreater(end, start)
        grid_js = self.panel[start:end]
        self.assertNotIn("fw-tip", grid_js,
                         "卡片网格的 innerHTML 里仍夹带 .fw-tip 说明")
        self.assertNotIn("统计口径", grid_js,
                         "统计口径说明仍被写进卡片网格")
        note_js = self.panel[end:end + 4000]
        self.assertIn("统计口径", note_js, "说明应写入 #fwStatsNote")
        self.assertIn("攻击类型封禁", note_js, "说明应写入 #fwStatsNote")

    def test_ban_subline_does_not_mix_list_size_with_active_bans(self):
        """副行不能把「名单条目数」与「生效封禁数」相加后称作「当前生效」。

        旧写法 `当前生效 (perm+temp)（临时 temp · 永久名单 perm）` 会让读者以为
        有 perm+temp 条封禁正在生效（黑名单条目数 ≠ 生效封禁数）。
        """
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertNotIn("'当前生效 '+(perm+temp)", text, name)
            self.assertNotIn("（临时 '+temp+' · 永久名单 '+perm+'）", text, name)
            # 新副行：分别标注名单规模与生效中的临时封禁数
            self.assertIn("'黑名单 '+perm+' 条 · 临时封禁 '+temp+' 条生效'", text, name)
            self.assertIn("不代表正在生效的封禁", text, name)

    def test_caliber_note_ties_subline_to_list_scale(self):
        """口径说明要显式区分「名单规模」与「生效封禁数」。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("名单规模", text, name)
            self.assertIn("真正生效中的封禁数只看「生效封禁」卡片", text, name)


if __name__ == "__main__":
    unittest.main()
