from __future__ import annotations

import importlib.util
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "agent_reach" / "social_readonly.py"
SPEC = importlib.util.spec_from_file_location("potato_social_readonly_test_module", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
social = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = social
SPEC.loader.exec_module(social)


class SocialReadOnlyDecisionTests(unittest.TestCase):
    def assert_allowed(self, *argv: str) -> None:
        decision = social.check_social_command(argv)
        self.assertTrue(decision.allowed, decision.reason)

    def assert_blocked(self, *argv: str) -> None:
        decision = social.check_social_command(argv)
        self.assertFalse(decision.allowed, decision.reason)
        with self.assertRaises(social.SocialWriteBlocked):
            social.require_read_only(argv)

    def test_twitter_read_commands_allowed(self):
        for action in (
            "feed",
            "bookmarks",
            "search",
            "user",
            "user-posts",
            "tweet",
            "article",
            "followers",
            "following",
            "whoami",
        ):
            with self.subTest(action=action):
                self.assert_allowed("twitter", action, "placeholder")

    def test_twitter_write_commands_blocked(self):
        for action in (
            "post",
            "reply",
            "quote",
            "delete",
            "like",
            "unlike",
            "bookmark",
            "unbookmark",
            "retweet",
            "unretweet",
            "follow",
            "unfollow",
        ):
            with self.subTest(action=action):
                self.assert_blocked("twitter", action, "placeholder")

    def test_reddit_read_allowed_and_mutations_blocked(self):
        for action in ("search", "read", "sub", "popular", "user", "saved", "upvoted"):
            with self.subTest(action=action):
                self.assert_allowed("rdt", action, "placeholder")
        for action in ("upvote", "save", "subscribe", "comment"):
            with self.subTest(action=action):
                self.assert_blocked("rdt", action, "placeholder")

    def test_bilibili_mutations_blocked(self):
        for action in ("dynamic-post", "dynamic-delete", "like", "coin", "triple", "unfollow"):
            with self.subTest(action=action):
                self.assert_blocked("bili", action, "placeholder")
        for action in ("search", "video", "hot", "rank", "feed", "favorites"):
            with self.subTest(action=action):
                self.assert_allowed("bili", action, "placeholder")

    def test_xhs_fail_closed(self):
        for action in ("search", "read", "comments", "feed", "hot"):
            with self.subTest(action=action):
                self.assert_allowed("xhs", action, "placeholder")
        for action in ("post", "publish", "like", "follow", "comment", "delete"):
            with self.subTest(action=action):
                self.assert_blocked("xhs", action, "placeholder")
        self.assert_blocked("xhs", "future-unknown-command")

    def test_opencli_social_allowlists(self):
        self.assert_allowed("opencli", "twitter", "search", "ai")
        self.assert_allowed("opencli", "reddit", "read", "abc")
        self.assert_allowed("opencli", "facebook", "feed")
        self.assert_allowed("opencli", "instagram", "explore")
        self.assert_allowed("opencli", "xiaohongshu", "note", "url")

        for argv in (
            ("opencli", "twitter", "post", "hello"),
            ("opencli", "reddit", "comment", "abc", "hello"),
            ("opencli", "facebook", "like", "abc"),
            ("opencli", "instagram", "follow", "abc"),
            ("opencli", "xiaohongshu", "publish", "hello"),
            ("opencli", "linkedin", "message", "hello"),
        ):
            with self.subTest(argv=argv):
                self.assert_blocked(*argv)

    def test_opencli_non_social_is_not_broken(self):
        self.assert_allowed("opencli", "some-non-social-platform", "read", "x")

    def test_mcporter_social_tools_fail_closed(self):
        self.assert_allowed("mcporter", "call", "xiaohongshu.check_login_status")
        self.assert_allowed("mcporter", "call", "xiaohongshu.search_feeds", 'keyword="ai"')
        self.assert_allowed("mcporter", "call", "xiaohongshu.get_feed_detail", "feed_id=1")
        self.assert_allowed("mcporter", "call", "linkedin.search_people", 'query="ai"')

        for tool in (
            "xiaohongshu.like_feed",
            "xiaohongshu.post_comment",
            "xiaohongshu.create_note",
            "linkedin.send_message",
            "linkedin.follow_user",
        ):
            with self.subTest(tool=tool):
                self.assert_blocked("mcporter", "call", tool)

    def test_non_social_mcporter_call_is_untouched(self):
        self.assert_allowed("mcporter", "call", "exa.search", 'query="ai"')

    def test_help_is_allowed(self):
        for binary in ("twitter", "rdt", "bili", "xhs", "opencli", "mcporter"):
            with self.subTest(binary=binary):
                self.assert_allowed(binary, "--help")


class WrapperInstallTests(unittest.TestCase):
    def test_wrapper_install_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = social.install_wrappers(tmp)
            self.assertEqual(target, Path(tmp) / ".agent-reach" / "readonly-bin")
            for binary in social.WRAPPER_BINARIES:
                path = target / binary
                self.assertTrue(path.is_file())
                mode = path.stat().st_mode
                self.assertTrue(mode & stat.S_IXUSR)

            activation = social.activation_line(tmp)
            self.assertIn(str(target), activation)
            self.assertIn("$PATH", activation)

            social.uninstall_wrappers(tmp)
            for binary in social.WRAPPER_BINARIES:
                self.assertFalse((target / binary).exists())


if __name__ == "__main__":
    unittest.main()
