#!/usr/bin/env python3
"""Rotating the session key must not log anybody out.

That is the whole point of the keyring, and it is the property that is easy to
lose in a later refactor: someone simplifies verification_secrets() down to the
current key, every test that only checks "a fresh token works" still passes, and
the first scheduled rotation throws every administrator out of the WebUI at
03:30 on a Sunday.

So the central test here signs a token, rotates, and demands that the OLD token
still verifies. Everything else is supporting detail.

Runs with no hardware and no manager import -- the keyring is deliberately a
standalone module so this suite needs neither fastapi nor a database.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "opt"))

import ffn_jwt_keys as K  # noqa: E402

NOW = 1_000_000
LIFETIME = 480          # must mirror ffn_manager.JWT_EXPIRE_MINUTES


class Overlap(unittest.TestCase):
    def test_a_token_signed_before_rotation_still_verifies(self):
        ring = K.empty(NOW)
        signed_with = K.signing_secret(ring)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, now=NOW)
        self.assertIn(signed_with, K.verification_secrets(ring, NOW),
                      "rotation invalidated a live session")
        self.assertNotEqual(K.signing_secret(ring), signed_with,
                            "rotation did not actually change the signing key")

    def test_overlap_lasts_the_token_lifetime_plus_margin(self):
        ring = K.empty(NOW)
        old = K.signing_secret(ring)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, now=NOW)
        edge = NOW + (LIFETIME + K.RETIRE_MARGIN_MINUTES) * 60
        self.assertIn(old, K.verification_secrets(ring, edge - 1))
        self.assertNotIn(old, K.verification_secrets(ring, edge + 1),
                         "a retired key outlived every token it could sign")

    def test_margin_exceeds_zero(self):
        """Without margin, a token minted in the same second as a rotation can
        outlive its key by the clock skew between two machines."""
        self.assertGreater(K.RETIRE_MARGIN_MINUTES, 0)

    def test_two_rotations_inside_one_lifetime_keep_both_predecessors(self):
        ring = K.empty(NOW)
        first = K.signing_secret(ring)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, now=NOW)
        second = K.signing_secret(ring)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, now=NOW + 60)
        live = K.verification_secrets(ring, NOW + 60)
        self.assertIn(first, live)
        self.assertIn(second, live)
        self.assertEqual(len(live), 3)

    def test_current_is_tried_first(self):
        """Nearly every token presented was signed by the current key."""
        ring = K.rotate(K.empty(NOW), lifetime_minutes=LIFETIME, now=NOW)
        self.assertEqual(K.verification_secrets(ring, NOW)[0],
                         K.signing_secret(ring))


class Compromise(unittest.TestCase):
    def test_compromised_revokes_immediately(self):
        ring = K.empty(NOW)
        leaked = K.signing_secret(ring)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, compromised=True, now=NOW)
        self.assertNotIn(leaked, K.verification_secrets(ring, NOW),
                         "a key believed compromised was still accepted")
        self.assertEqual(len(K.verification_secrets(ring, NOW)), 1)

    def test_compromised_drops_older_retired_keys_too(self):
        ring = K.rotate(K.empty(NOW), lifetime_minutes=LIFETIME, now=NOW)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, compromised=True, now=NOW + 60)
        self.assertEqual(len(K.verification_secrets(ring, NOW + 60)), 1)


class Persistence(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ffnjwtkeys")
        self.path = os.path.join(self.dir, "jwt.keys")

    @unittest.skipUnless(os.name == "posix",
                         "file modes are not meaningful off POSIX; the "
                         "appliance and CI are both Linux, where this runs")
    def test_keyring_is_not_readable_by_anyone_else(self):
        ring = K.rotate(K.empty(NOW), lifetime_minutes=LIFETIME, now=NOW)
        K.save(ring, self.path)
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), oct(0o600),
                         "the signing keyring must not be readable by anyone else")

    def test_round_trip(self):
        ring = K.rotate(K.empty(NOW), lifetime_minutes=LIFETIME, now=NOW)
        K.save(ring, self.path)
        back = K.load(self.path)
        self.assertEqual(K.signing_secret(back), K.signing_secret(ring))
        self.assertEqual(K.verification_secrets(back, NOW),
                         K.verification_secrets(ring, NOW))

    def test_missing_and_corrupt_files_are_not_a_keyring(self):
        self.assertIsNone(K.load(os.path.join(self.dir, "absent")))
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertIsNone(K.load(self.path))
        with open(self.path, "w") as fh:
            fh.write('{"version":1,"current":{}}')
        self.assertIsNone(K.load(self.path), "a keyring with no secret is not usable")

    def test_load_cached_notices_a_rotation(self):
        """The manager reads through load_cached on every request; if it did not
        notice a rotation the overlap would be pointless -- it would keep
        verifying against the keyring it read at import."""
        K.save(K.empty(NOW), self.path)
        first = K.signing_secret(K.load_cached(self.path))
        K.save(K.rotate(K.load(self.path), lifetime_minutes=LIFETIME), self.path)
        second = K.signing_secret(K.load_cached(self.path))
        self.assertNotEqual(first, second, "load_cached served a stale keyring")

    def test_save_is_atomic_and_leaves_no_temp(self):
        K.save(K.empty(NOW), self.path)
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".tmp")], [])


class Adoption(unittest.TestCase):
    def test_adopt_keeps_the_existing_secret_current(self):
        ring = K.adopt("the-secret-the-box-is-already-using", NOW)
        self.assertEqual(K.signing_secret(ring),
                         "the-secret-the-box-is-already-using")
        self.assertEqual(K.verification_secrets(ring, NOW),
                         ["the-secret-the-box-is-already-using"])

    def test_first_rotation_after_adoption_still_overlaps(self):
        ring = K.adopt("existing", NOW)
        ring = K.rotate(ring, lifetime_minutes=LIFETIME, now=NOW)
        self.assertIn("existing", K.verification_secrets(ring, NOW),
                      "migrating then rotating logged everyone out")


class Hygiene(unittest.TestCase):
    def test_generated_secrets_are_distinct_and_long(self):
        seen = {K.new_secret() for _ in range(50)}
        self.assertEqual(len(seen), 50, "secrets repeated")
        self.assertTrue(all(len(s) >= 40 for s in seen))

    def test_prune_reports_what_it_dropped(self):
        ring = K.rotate(K.empty(NOW), lifetime_minutes=1, now=NOW)
        self.assertEqual(K.prune(ring, NOW), 0)
        self.assertEqual(K.prune(ring, NOW + (1 + K.RETIRE_MARGIN_MINUTES) * 60 + 1), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
