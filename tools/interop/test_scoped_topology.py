import json
import unittest
from unittest.mock import patch

from scoped_topology import Topology, success


class CleanupOwnership(unittest.TestCase):
    def topology(self, pids="", links="[]", ns_links="[]"):
        report = {}
        value = Topology(report)
        value.created = {"owned-c": [1, 2]}
        commands = []
        def command(*argv):
            commands.append(argv)
            if argv[:3] == ("ip", "netns", "pids"):
                return pids
            if argv == ("ip", "-j", "link"):
                return links
            if argv == ("ip", "-n", "owned-c", "-j", "link"):
                return ns_links
            return ""
        value.command = command
        return value, report, commands

    def test_only_verified_empty_namespace_is_deleted(self):
        value, report, commands = self.topology()
        with patch("scoped_topology.namespace_identity", return_value=[1, 2]), patch("pathlib.Path.exists", return_value=True):
            value.cleanup()
        self.assertIn(("ip", "netns", "delete", "owned-c"), commands)
        self.assertTrue(report["cleanup"]["complete"])

    def test_changed_namespace_or_unknown_process_is_retained(self):
        for identity, pids in (([9, 9], ""), ([1, 2], "1234\n")):
            value, report, commands = self.topology(pids)
            with patch("scoped_topology.namespace_identity", return_value=identity), patch("pathlib.Path.exists", return_value=True):
                value.cleanup()
            self.assertFalse(any(argv[:3] == ("ip", "netns", "delete") for argv in commands))
            self.assertFalse(report["cleanup"]["complete"])

    def test_reused_host_interface_name_is_retained(self):
        value, report, commands = self.topology(links='[{"ifname":"owned-veth","ifindex":7,"ifalias":"another-owner"}]')
        value.created.clear()
        value.interfaces["owned-veth"] = {"namespace":None,"name":"owned-veth",
            "ifindex":7,"alias":value.token,"peer":"owned-veth"}
        value.cleanup()
        self.assertFalse(any(argv[:3] == ("ip", "link", "delete") for argv in commands))
        self.assertFalse(report["cleanup"]["complete"])

    def test_unknown_namespace_interface_retains_everything(self):
        value, report, commands = self.topology(ns_links='[{"ifname":"foreign0","ifindex":5}]')
        with patch("scoped_topology.namespace_identity", return_value=[1, 2]), patch("pathlib.Path.exists", return_value=True):
            value.cleanup()
        self.assertFalse(report["cleanup"]["complete"])
        self.assertFalse(any("delete" in argv for argv in commands))

    def test_changed_namespace_interface_identity_or_peer_retains(self):
        for alteration in ({"ifindex":99}, {"ifalias":"foreign"}, {"link_index":99}):
            value, report, commands = self.topology()
            value.interfaces["a"] = {"namespace":"owned-c","name":"c0","ifindex":7,
                                      "alias":value.token,"peer":"b"}
            value.interfaces["b"] = {"namespace":None,"name":"b","ifindex":8,
                                      "alias":value.token,"peer":"a"}
            row = dict(ifname="c0",ifindex=7,ifalias=value.token,link_index=8)
            row.update(alteration)
            original = value.command
            value.command = lambda *argv: json.dumps([row]) if argv == ("ip","-n","owned-c","-j","link") else original(*argv)
            with patch("scoped_topology.namespace_identity", return_value=[1, 2]), patch("pathlib.Path.exists", return_value=True):
                value.cleanup()
            self.assertFalse(report["cleanup"]["complete"])
            self.assertFalse(any("delete" in argv for argv in commands))

    def test_host_pair_deletion_requeries_before_next_pair(self):
        value, report, commands = self.topology()
        value.created.clear()
        rows = []
        for key, index, peer, peer_index in (("a",7,"b",8),("b",8,"a",7),("c",9,"d",10),("d",10,"c",9)):
            value.interfaces[key] = {"namespace":None,"name":key,"ifindex":index,"alias":value.token,"peer":peer}
            rows.append(dict(ifname=key,ifindex=index,ifalias=value.token,link_index=peer_index))
        def command(*argv):
            commands.append(argv)
            if argv == ("ip","-j","link"):
                return json.dumps(rows)
            if argv[:3] == ("ip","link","delete"):
                names = {argv[-1], value.interfaces[argv[-1]]["peer"]}
                rows[:] = [row for row in rows if row["ifname"] not in names]
            return ""
        value.command = command
        value.cleanup()
        self.assertTrue(report["cleanup"]["complete"])
        self.assertEqual([argv[-1] for argv in commands if "delete" in argv], ["a","c"])
        self.assertEqual(commands.count(("ip","-j","link")), 3)

    def test_known_peer_missing_after_namespace_cleanup_is_allowed(self):
        value = Topology({})
        value.created = {"owned-c":[1,2],"owned-r":[3,4]}
        rows = {}
        for key, namespace, index, peer, peer_index in (("a","owned-c",7,"b",8),("b","owned-r",8,"a",7)):
            value.interfaces[key] = {"namespace":namespace,"name":key,"ifindex":index,"alias":value.token,"peer":peer}
            rows[namespace] = [dict(ifname=key,ifindex=index,ifalias=value.token,link_index=peer_index)]
        deleted = []
        def command(*argv):
            if argv[:2] == ("ip","-n"):
                return json.dumps(rows[argv[2]])
            if argv[:3] == ("ip","netns","delete"):
                deleted.append(argv[-1])
                rows["owned-c"] = []
                rows["owned-r"] = []
            return "[]" if argv == ("ip","-j","link") else ""
        value.command = command
        with patch("scoped_topology.namespace_identity", side_effect=lambda name:value.created[name]), patch("pathlib.Path.exists", return_value=True):
            value.cleanup()
        self.assertTrue(value.report["cleanup"]["complete"])
        self.assertEqual(deleted, ["owned-r","owned-c"])

    def test_partial_move_and_rename_have_current_ledger(self):
        for failure in ("rename", "addrgenmode", "moved-read"):
            value = Topology({})
            def command(*argv):
                if "netns" in argv and "set" in argv:
                    return ""
                if "name" in argv and "set" in argv and failure == "rename":
                    raise RuntimeError("rename refused")
                if "addrgenmode" in argv and failure == "addrgenmode":
                    raise RuntimeError("configuration refused")
                if "-j" in argv:
                    if "-n" in argv:
                        if failure == "moved-read":
                            raise RuntimeError("query refused")
                        return json.dumps([{"ifindex":20,"ifalias":value.token}])
                    return json.dumps([{"ifindex":7 if argv[-1].endswith("a") else 8}])
                return ""
            value.command = command
            with self.assertRaises(RuntimeError):
                value.pair("c","c0","r","r0","l")
            entry = next(iter(value.interfaces.values()))
            self.assertEqual(entry["namespace"], value.names["c"])
            self.assertEqual(entry["name"], "c0" if failure == "addrgenmode" else next(iter(value.interfaces)))
            self.assertEqual(entry["ifindex"], None if failure == "moved-read" else 20)

    def test_delayed_owned_peer_removal_is_allowed_but_replacement_is_not(self):
        for replacement in (False, True):
            value = Topology({})
            value.created = {"owned-c":[1,2],"owned-r":[3,4]}
            rows = {}
            for key, namespace, index, peer, peer_index in (("a","owned-c",7,"b",8),("b","owned-r",8,"a",7)):
                value.interfaces[key] = {"namespace":namespace,"name":key,"ifindex":index,"alias":value.token,"peer":peer}
                rows[namespace] = [dict(ifname=key,ifindex=index,ifalias=value.token,link_index=peer_index)]
            deleted = []
            def command(*argv):
                if argv[:2] == ("ip","-n"):
                    return json.dumps(rows[argv[2]])
                if argv[:3] == ("ip","netns","delete"):
                    deleted.append(argv[-1])
                    if replacement:
                        rows["owned-c"][0]["ifalias"] = "foreign"
                return "[]" if argv == ("ip","-j","link") else ""
            value.command = command
            with patch("scoped_topology.namespace_identity", side_effect=lambda name:value.created[name]), patch("pathlib.Path.exists", return_value=True):
                value.cleanup()
            self.assertEqual(value.report["cleanup"]["complete"], not replacement)
            self.assertEqual(deleted, ["owned-r"] if replacement else ["owned-r","owned-c"])

    def test_received_nonzero_scope_cannot_be_replaced_with_zero(self):
        value = {"exit":0,"records":[{"event":"complete","code":69,"hex":b"coaptic-scoped-addressing".hex()},
                                     {"event":"receive","scope_id":7}]}
        success(value, 7)
        value["records"][1]["scope_id"] = 0
        with self.assertRaises(ValueError):
            success(value, 7)


if __name__ == "__main__":
    unittest.main()
