from app.chat.status_queries import asks_active_deployment_summary


def test_active_deployment_summary_query_is_recognized():
    assert asks_active_deployment_summary("只查询：当前有没有正在执行的发布任务？")
    assert asks_active_deployment_summary("现在有几个项目正在部署")


def test_project_action_is_not_misclassified_as_global_status_query():
    assert not asks_active_deployment_summary("重新发布 crm")
    assert not asks_active_deployment_summary("停止这个部署任务")
