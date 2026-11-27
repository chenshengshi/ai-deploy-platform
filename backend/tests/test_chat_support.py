import unittest

from app.chat_support import extract_external_mysql_config, format_failure_diagnosis


class ChatSupportTests(unittest.TestCase):
    def test_extract_external_mysql_config_from_chinese_request(self):
        config = extract_external_mysql_config(
            "把仓储改为外置 MySQL：地址 192.168.4.16，端口 60306，"
            "数据库 wms，用户名 root，密码 example_secret。清理旧托管数据卷。"
        )
        self.assertEqual("external", config["YUNZHOU_MYSQL_MODE"])
        self.assertEqual("192.168.4.16", config["YUNZHOU_MYSQL_HOST"])
        self.assertEqual("60306", config["YUNZHOU_MYSQL_PORT"])
        self.assertEqual("wms", config["YUNZHOU_MYSQL_DATABASE"])
        self.assertEqual("root", config["YUNZHOU_MYSQL_USERNAME"])
        self.assertEqual("example_secret", config["YUNZHOU_MYSQL_PASSWORD"])

    def test_external_mysql_requires_complete_explicit_connection(self):
        self.assertEqual({}, extract_external_mysql_config("改成外置 MySQL，地址 192.168.4.16"))

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
