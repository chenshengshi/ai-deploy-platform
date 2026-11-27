import unittest

from app.project_data.sql_safety import extract_direct_sql, is_high_risk_sql, sql_kind


class SqlSafetyTests(unittest.TestCase):
    def test_extracts_sql_after_chinese_prefix(self):
        self.assertEqual("SELECT * FROM users", extract_direct_sql("帮我执行SELECT * FROM users"))

    def test_read_only_query_rejects_hidden_second_statement(self):
        self.assertEqual("query", sql_kind("SELECT * FROM users"))
        self.assertEqual("unsupported", sql_kind("SELECT * FROM users; DELETE FROM users"))

    def test_high_risk_schema_change(self):
        self.assertTrue(is_high_risk_sql("ALTER TABLE users DROP COLUMN name"))


if __name__ == "__main__":
    unittest.main()
