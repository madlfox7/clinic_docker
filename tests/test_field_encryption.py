import json
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest

from tests.field_key import decrypt, field_crypto, is_packet, stand_keyring
from tests.test_rls_boundary import compose_exec
from tests.test_stage4 import (
	ADMIN,
	DOC,
	DOC2,
	PAT,
	REG,
	_drop_visit,
	_past_visit,
	client,
	login,
	psql,
)

ROOT = Path(__file__).resolve().parents[1]


def _record(doctor, visit, record_type, text):
	saved = doctor.post(
		f"/doctor/appointments/{visit}/records",
		data={"record_type": record_type, "body": text},
	)
	assert f"saved={record_type}" in str(saved.url), saved.url


def test_medical_text_is_stored_encrypted_and_shown_as_plaintext():
	marker = uuid.uuid4().hex[:10]
	note = f"Sore throat, gargle warm saline {marker}"
	prescription = f"Amoxicillin 500 mg three times a day {marker}"
	visit = _past_visit(DOC)
	try:
		with client() as doctor, client() as pat, client() as other_doctor, \
				client() as registrar, client() as admin:
			login(doctor, DOC)
			login(pat, PAT)
			login(other_doctor, DOC2)
			login(registrar, REG)
			login(admin, ADMIN)
			_record(doctor, visit, "note", note)
			_record(doctor, visit, "prescription", prescription)

			current_id = stand_keyring().current_id
			for table, text in (("visit_notes", note), ("prescriptions", prescription)):
				stored = psql(f"SELECT body FROM {table} WHERE appointment_id = {visit}")
				assert marker not in stored and "throat" not in stored and "mg" not in stored
				assert is_packet(stored), "body is not an encrypted packet"
				assert stored.startswith(f"fe1:{current_id}:")
				assert decrypt(table, stored) == text

			dump = subprocess.run(
				["docker", "compose", "exec", "-T", "db", "pg_dump", "-U", "clinic",
				 "-d", "clinic", "--data-only", "-t", "visit_notes", "-t", "prescriptions"],
				cwd=ROOT, capture_output=True, text=True,
			)
			assert dump.returncode == 0, dump.stderr
			assert "fe1:" in dump.stdout
			assert marker not in dump.stdout

			record_url = f"/doctor/appointments/{visit}/records"
			patient_id = psql(f"SELECT id FROM users WHERE email = '{PAT}'")
			for page in (
				doctor.get(record_url).text,
				doctor.get(f"/doctor/patients/{patient_id}").text,
				pat.get("/my/records").text,
				pat.get("/my").text,
			):
				assert note in page and prescription in page
				assert "fe1:" not in page

			for page in (
				other_doctor.get(record_url).text,
				registrar.get(record_url).text,
				registrar.get("/admin/audit").text,
				admin.get(record_url).text,
				admin.get("/admin/audit").text,
				admin.get("/my/records").text,
			):
				assert marker not in page
				assert "fe1:" not in page
	finally:
		_drop_visit(visit)


def test_unreadable_packet_gives_clear_error_without_details():
	visit = _past_visit(DOC)
	try:
		# A packet from another key (not on this stand) cannot be decrypted.
		foreign = field_crypto.Keyring.from_texts("other:" + os.urandom(32).hex())
		packet = foreign.encrypt("visit_notes", "foreign-key-text")
		psql(
			"INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body) "
			f"SELECT id, doctor_id, patient_user_id, '{packet}' FROM appointments WHERE id = {visit}"
		)
		with client() as doctor:
			login(doctor, DOC)
			page = doctor.get(f"/doctor/appointments/{visit}/records")
		assert page.status_code == 500
		assert "could not be decrypted" in page.text
		assert "fe1:" not in page.text and "Traceback" not in page.text
		logs = subprocess.run(
			["docker", "compose", "logs", "--since", "2m", "api"],
			cwd=ROOT, capture_output=True, text=True,
		).stdout
		assert "reason=unknown_key_id" in logs
		assert packet not in logs and "Traceback" not in logs
	finally:
		_drop_visit(visit)


def _drop_body_check(table):
	psql(f"ALTER TABLE {table} DROP CONSTRAINT {table}_body_encrypted_check")


def _restore_schema():
	# Rerun the normal migrate service: init.sql recreates the NOT VALID check.
	completed = subprocess.run(
		["docker", "compose", "run", "--rm", "--no-deps", "-T", "migrate"],
		cwd=ROOT, capture_output=True, text=True,
	)
	assert completed.returncode == 0, completed.stderr[-2000:]


def test_api_migration_encrypts_legacy_plaintext_once():
	marker = uuid.uuid4().hex[:10]
	legacy_note = f"legacy plaintext note {marker}"
	legacy_rx = f"legacy plaintext prescription {marker}"
	visit = _past_visit(DOC)
	try:
		# An older volume still holds plaintext rows (written before this check existed).
		_drop_body_check("visit_notes")
		_drop_body_check("prescriptions")
		for table, text in (("visit_notes", legacy_note), ("prescriptions", legacy_rx)):
			psql(
				f"INSERT INTO {table} (appointment_id, doctor_id, patient_user_id, body) "
				f"SELECT id, doctor_id, patient_user_id, '{text}' FROM appointments WHERE id = {visit}"
			)
		_restore_schema()

		first = compose_exec("api", ["python", "-m", "migrate_medical_fields"])
		assert "visit_notes: 1 encrypted" in first and "prescriptions: 1 encrypted" in first
		assert marker not in first
		second = compose_exec("api", ["python", "-m", "migrate_medical_fields"])
		assert "visit_notes: 0 encrypted" in second and "prescriptions: 0 encrypted" in second

		for table, text in (("visit_notes", legacy_note), ("prescriptions", legacy_rx)):
			stored = psql(f"SELECT body FROM {table} WHERE appointment_id = {visit}")
			assert marker not in stored and is_packet(stored)
			assert decrypt(table, stored) == text
		# No plaintext row is left anywhere: the packet check validates.
		psql(
			"BEGIN;"
			" ALTER TABLE visit_notes VALIDATE CONSTRAINT visit_notes_body_encrypted_check;"
			" ALTER TABLE prescriptions VALIDATE CONSTRAINT prescriptions_body_encrypted_check;"
			" ROLLBACK;"
		)
		with client() as pat:
			login(pat, PAT)
			page = pat.get("/my/records").text
		assert legacy_note in page and legacy_rx in page
	finally:
		_drop_visit(visit)
		if psql(
			"SELECT count(*) FROM pg_constraint "
			"WHERE conname IN ('visit_notes_body_encrypted_check', 'prescriptions_body_encrypted_check')"
		) != "2":
			_restore_schema()


def test_migration_functions_are_only_for_the_api_login():
	for role in ("app_doctor", "app_patient", "app_admin", "app_registrar"):
		denied = subprocess.run(
			["docker", "compose", "exec", "-T", "db", "psql", "-X", "-U", "clinic", "-d", "clinic",
			 "-v", "ON_ERROR_STOP=1", "-At", "-c",
			 f"BEGIN; SET LOCAL ROLE {role}; "
			 "SELECT * FROM public.medical_bodies_to_encrypt('visit_notes', 'v1', true, 0, 10);"],
			cwd=ROOT, capture_output=True, text=True,
		)
		assert denied.returncode != 0 and "permission denied" in denied.stderr
	script = """
import json
import psycopg2
from db import db, db_as
result = {}
conn = db()
with conn.cursor() as cur:
    cur.execute("SELECT id, role FROM users WHERE email = 'doc@clinic.local'")
    doctor_id, role = cur.fetchone()
conn.close()
conn = db_as({"id": doctor_id, "role": role})
try:
    with conn.cursor() as cur:
        cur.execute("SELECT public.medical_body_replace('visit_notes', 1, 'x', 'y')")
    result["doctor"] = "allowed"
except psycopg2.Error as exc:
    result["doctor"] = exc.pgcode
finally:
    conn.close()
conn = db()
try:
    with conn.cursor() as cur:
        cur.execute("SELECT public.medical_body_replace('visit_notes', 1, 'x', 'plaintext')")
    result["plaintext"] = "allowed"
except psycopg2.Error as exc:
    result["plaintext"] = exc.pgcode
finally:
    conn.close()
print(json.dumps(result))
"""
	result = json.loads(compose_exec("api", ["python", "-"], input_text=script))
	assert result == {"doctor": "42501", "plaintext": "42501"}


def test_rotation_keeps_old_rows_readable_and_writes_new_key_id():
	# Unit level: a keyring with an old and a current key.
	old_line = "v1:" + os.urandom(32).hex()
	new_line = "v2:" + os.urandom(32).hex()
	old_ring = field_crypto.Keyring.from_texts(old_line)
	rotated = field_crypto.Keyring.from_texts(new_line, f"# kept for reading\n{old_line}\n")
	old_packet = old_ring.encrypt("visit_notes", "written before rotation")
	assert rotated.decrypt("visit_notes", old_packet) == "written before rotation"
	new_packet = rotated.encrypt("visit_notes", "written after rotation")
	assert field_crypto.packet_key_id(new_packet) == "v2"
	with pytest.raises(field_crypto.FieldDecryptError):
		old_ring.decrypt("visit_notes", new_packet)
	with pytest.raises(field_crypto.FieldDecryptError):
		rotated.decrypt("prescriptions", old_packet)  # bound to its table
	tampered = old_packet[:-3] + ("AAA" if not old_packet.endswith("AAA") else "BBB")
	with pytest.raises(field_crypto.FieldDecryptError):
		rotated.decrypt("visit_notes", tampered)
	with pytest.raises(field_crypto.FieldKeyError):
		field_crypto.Keyring.from_texts(new_line, "v2:" + os.urandom(32).hex())

	# Stand level: re-encrypt real rows with a new current key inside the api,
	# through the same SQL functions as the startup migration, then roll back.
	marker = uuid.uuid4().hex[:10]
	visit = _past_visit(DOC)
	try:
		with client() as doctor:
			login(doctor, DOC)
			_record(doctor, visit, "note", f"rotation note {marker}")
		row_id = int(psql(f"SELECT id FROM visit_notes WHERE appointment_id = {visit}"))
		script = """
import json, os
from db import db
from field_crypto import Keyring, load_keyring
from migrate_medical_fields import migrate
from secret_files import read_secret

stand = load_keyring()
rotated = Keyring.from_texts(
    "rottest:" + os.urandom(32).hex(),
    read_secret("field_encryption_key") + "\\n" + read_secret("field_encryption_previous_keys"),
)
conn = db()
try:
    counts = migrate(conn, rotated, reencrypt=True)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, body FROM public.medical_bodies_to_encrypt('visit_notes', %s, true, 0, 1000)",
            (stand.current_id,),
        )
        body = dict(cur.fetchall())[__ROW_ID__]
    result = {
        "counts": counts,
        "key_id": body.split(":")[1],
        "text": rotated.decrypt("visit_notes", body),
    }
    try:
        stand.decrypt("visit_notes", body)
        result["stand_reads_new"] = True
    except Exception:
        result["stand_reads_new"] = False
finally:
    conn.rollback()
    conn.close()
print(json.dumps(result))
""".replace("__ROW_ID__", str(row_id))
		result = json.loads(compose_exec("api", ["python", "-"], input_text=script))
		assert result["key_id"] == "rottest"
		assert result["text"] == f"rotation note {marker}"
		assert result["stand_reads_new"] is False
		assert result["counts"]["visit_notes"]["encrypted"] >= 1
		assert result["counts"]["visit_notes"]["failed"] == 0
		# rolled back: the stand still reads the row with its own key
		stored = psql(f"SELECT body FROM visit_notes WHERE id = {row_id}")
		assert decrypt("visit_notes", stored) == f"rotation note {marker}"
	finally:
		_drop_visit(visit)


def _not_world_readable(path: Path) -> bool:
	return not (path.stat().st_mode & (stat.S_IROTH | stat.S_IWOTH))


def test_rotate_script_keeps_old_key_and_prints_no_values(tmp_path):
	(tmp_path / "scripts").mkdir()
	for name in ("init_secrets.sh", "rotate_field_key.sh"):
		shutil.copy2(ROOT / "scripts" / name, tmp_path / "scripts" / name)
	run = lambda *cmd: subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True)

	first = run("./scripts/init_secrets.sh")
	assert first.returncode == 0, first.stderr
	key_file = tmp_path / "secrets" / "field_encryption_key"
	previous_file = tmp_path / "secrets" / "field_encryption_previous_keys"
	v1 = key_file.read_text()
	assert v1.startswith("v1:") and previous_file.read_text() == ""
	assert v1.split(":", 1)[1] not in first.stdout + first.stderr
	assert _not_world_readable(key_file) and _not_world_readable(previous_file)

	again = run("./scripts/init_secrets.sh")
	assert again.returncode == 0 and key_file.read_text() == v1
	assert "keep    secrets/field_encryption_key" in again.stdout

	rotated = run("./scripts/rotate_field_key.sh")
	assert rotated.returncode == 0, rotated.stderr
	v2 = key_file.read_text()
	assert v2.startswith("v2:") and v2 != v1
	assert v1 in previous_file.read_text()
	for secret in (v1, v2, v1.split(":", 1)[1], v2.split(":", 1)[1]):
		assert secret not in rotated.stdout + rotated.stderr
	assert _not_world_readable(key_file) and _not_world_readable(previous_file)
	ring = field_crypto.Keyring.from_texts(v2, previous_file.read_text())
	assert ring.current_id == "v2" and ring.key_ids == ["v1", "v2"]

	reused = run("./scripts/rotate_field_key.sh", "v1")
	assert reused.returncode != 0 and key_file.read_text() == v2
