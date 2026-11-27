import unittest

from app.chat_support import format_failure_diagnosis


class ChatSupportTests(unittest.TestCase):
    def test_failure_reply_uses_diagnosis_instead_of_outer_compose_noise(self):
        reply = format_failure_diagnosis("示例项目", "测试服务器", "202611271415", {
            "scope": "configuration",
            "summary": "后端容器启动失败：必填环境配置 AUTH_TOKEN_SECRET 未设置",
            "evidence": ["后端数据库配置缺失：AUTH_TOKEN_SECRET"],
            "advice": "补充 AUTH_TOKEN_SECRET 后重新发布",
        })

        self.assertIn("环境配置问题", reply)
        self.assertIn("AUTH_TOKEN_SECRET", reply)
        self.assertNotIn("Network", reply)
        self.assertIn("下一步：补充", reply)


if __name__ == "__main__":
    unittest.main()
