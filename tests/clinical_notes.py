

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NOTE_DOCTOR1_PATIENT_A = "note:doctor1-patientA"
NOTE_DOCTOR2_PATIENT_B = "note:doctor2-patientB"
DOC1_EMAIL = "doc@clinic.local"
DOC2_EMAIL = "doc2@clinic.local"
PATIENT_A_EMAIL = "pat@clinic.local"
PATIENT_B_EMAIL = "pat2@clinic.local"


def _psql(sql: str) -> str:
	completed = subprocess.run(
		[
			"docker", "compose", "exec", "-T", "db",
			"psql", "-U", "clinic", "-d", "clinic",
			"-v", "ON_ERROR_STOP=1", "-At", "-c", sql,
		],
		cwd=ROOT,
		capture_output=True,
		text=True,
	)
	if completed.returncode != 0:
		raise AssertionError(completed.stderr or completed.stdout)
	lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
	return lines[-1] if lines else ""


def cleanup_cross_doctor_notes() -> None:
	"""Remove the helper pair and any prescriptions attached to those appointments."""
	_psql(
		f"""
		DELETE FROM prescriptions
		WHERE appointment_id IN (
			SELECT id FROM appointments
			WHERE slot_id IN (
				SELECT id FROM slots
				WHERE starts_at IN (TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 11:00')
			)
			UNION
			SELECT appointment_id FROM visit_notes
			WHERE body IN ('{NOTE_DOCTOR1_PATIENT_A}', '{NOTE_DOCTOR2_PATIENT_B}')
		);
		DELETE FROM visit_notes
		WHERE body IN ('{NOTE_DOCTOR1_PATIENT_A}', '{NOTE_DOCTOR2_PATIENT_B}')
		   OR appointment_id IN (
				SELECT id FROM appointments
				WHERE slot_id IN (
					SELECT id FROM slots
					WHERE starts_at IN (TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 11:00')
				)
		   );
		DELETE FROM appointments
		WHERE slot_id IN (
			SELECT id FROM slots
			WHERE starts_at IN (TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 11:00')
		);
		DELETE FROM slots
		WHERE starts_at IN (TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 11:00');
		"""
	)


def insert_cross_doctor_notes() -> dict:
	"""One note for doctor 1 / patient A and one note for doctor 2 / patient B.

	doctor_id and patient_user_id are copied from the appointment on purpose.
	"""
	cleanup_cross_doctor_notes()
	row = _psql(
		f"""
		WITH doc1 AS (
			SELECT d.id AS doctor_id
			FROM doctors d
			JOIN users u ON u.id = d.user_id
			WHERE u.email = '{DOC1_EMAIL}'
		),
		doc2 AS (
			SELECT d.id AS doctor_id
			FROM doctors d
			JOIN users u ON u.id = d.user_id
			WHERE u.email = '{DOC2_EMAIL}'
		),
		patient_a AS (
			SELECT id AS patient_user_id FROM users WHERE email = '{PATIENT_A_EMAIL}'
		),
		patient_b AS (
			SELECT id AS patient_user_id FROM users WHERE email = '{PATIENT_B_EMAIL}'
		),
		slot_a AS (
			INSERT INTO slots (doctor_id, starts_at, ends_at)
			SELECT doctor_id, TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 09:30'
			FROM doc1
			RETURNING id, doctor_id
		),
		slot_b AS (
			INSERT INTO slots (doctor_id, starts_at, ends_at)
			SELECT doctor_id, TIMESTAMP '2042-04-07 11:00', TIMESTAMP '2042-04-07 11:30'
			FROM doc2
			RETURNING id, doctor_id
		),
		appt_a AS (
			INSERT INTO appointments
				(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
			SELECT slot_a.id, patient_a.patient_user_id, slot_a.doctor_id,
			       TIMESTAMP '2042-04-07 09:00', TIMESTAMP '2042-04-07 09:30', 'scheduled'
			FROM slot_a, patient_a
			RETURNING id, doctor_id, patient_user_id
		),
		appt_b AS (
			INSERT INTO appointments
				(slot_id, patient_user_id, doctor_id, starts_at, ends_at, status)
			SELECT slot_b.id, patient_b.patient_user_id, slot_b.doctor_id,
			       TIMESTAMP '2042-04-07 11:00', TIMESTAMP '2042-04-07 11:30', 'scheduled'
			FROM slot_b, patient_b
			RETURNING id, doctor_id, patient_user_id
		),
		note_a AS (
			INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
			SELECT id, doctor_id, patient_user_id, '{NOTE_DOCTOR1_PATIENT_A}'
			FROM appt_a
			RETURNING id, appointment_id
		),
		note_b AS (
			INSERT INTO visit_notes (appointment_id, doctor_id, patient_user_id, body)
			SELECT id, doctor_id, patient_user_id, '{NOTE_DOCTOR2_PATIENT_B}'
			FROM appt_b
			RETURNING id, appointment_id
		)
		SELECT note_a.id, note_b.id, note_a.appointment_id, note_b.appointment_id
		FROM note_a, note_b;
		"""
	)
	note_a, note_b, appt_a, appt_b = row.split("|")
	return {
		"note_a_id": int(note_a),
		"note_b_id": int(note_b),
		"appointment_a_id": int(appt_a),
		"appointment_b_id": int(appt_b),
	}
