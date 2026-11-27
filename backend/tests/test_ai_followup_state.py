import unittest
from types import SimpleNamespace

from app.ai import reconcile_followup_live_state
from app.models import DeployStatus


class AiFollowupLiveStateTests(unittest.TestCase):
    def test_gateway_fact_replaces_stale_missing_address_message(self):
        deployment = SimpleNamespace(status=DeployStatus.running, access_url=None)
        result, stage = reconcile_followup_live_state(
            {"source": "ai", "summary": "尚未识别访问地址", "evidence": []},
            deployment,
            "上传到服务器",
            "[阶段开始] verify\n[检查] 平台网关映射完成：http://example.test:30001\n",
        )

        self.assertEqual(stage, "验证访问")
        self.assertIn("http://example.test:30001", result["summary"])
        self.assertNotIn("尚未识别", result["summary"])

    def test_completed_pipeline_wins_over_stale_running_ai_result(self):
        deployment = SimpleNamespace(status=DeployStatus.running, access_url=None)
        result, stage = reconcile_followup_live_state(
            {"source": "ai", "summary": "正在拉取基础镜像", "evidence": []},
            deployment,
            "拉取基础镜像",
            "[完成] 部署成功，访问地址：http://example.test:30002\n",
        )

        self.assertEqual(stage, "部署完成")
        self.assertIn("部署成功", result["summary"])
        self.assertIn("http://example.test:30002", result["summary"])


if __name__ == "__main__":
    unittest.main()
