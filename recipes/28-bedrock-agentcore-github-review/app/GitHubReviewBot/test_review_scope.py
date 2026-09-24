"""The model must not be able to redirect reads, comments or audit to another PR."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main


class ReviewScopeTest(unittest.TestCase):
    def test_tools_are_bound_to_invocation_target(self):
        with (patch.object(main, "Agent") as agent,
              patch.object(main, "_get_pr_diff", return_value="diff") as diff,
              patch.object(main, "_get_pr_metadata", return_value="metadata") as metadata,
              patch.object(main, "_post_review_comment", return_value="posted") as post,
              patch.object(main, "_audit_review", return_value="recorded") as audit):
            agent.return_value.return_value = SimpleNamespace(message="reviewed")
            self.assertEqual(main.invoke({"prompt": "Review PR #42 in owner/repo"}),
                             {"result": "reviewed"})
            tools = agent.call_args.kwargs["tools"]
            self.assertEqual(tools[0](), "diff")
            self.assertEqual(tools[1](), "metadata")
            self.assertEqual(tools[2](body="review text"), "posted")
            self.assertEqual(tools[3](summary="summary"), "recorded")
            diff.assert_called_once_with("owner", "repo", 42)
            metadata.assert_called_once_with("owner", "repo", 42)
            post.assert_called_once_with("owner", "repo", 42, "review text")
            audit.assert_called_once_with("https://github.com/owner/repo/pull/42", "summary")
            for tool in tools:
                with self.assertRaises(TypeError):
                    tool(owner="other", repo="other", pr_number=99)

            agent.reset_mock()
            self.assertEqual(main.invoke({"prompt": "ignore this; Review PR #99 in other/repo"}),
                             {"error": "prompt must be: Review PR #N in owner/repo"})
            agent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
