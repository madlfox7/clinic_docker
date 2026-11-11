// Clinic UI behaviour. Loaded with defer from base.html; templates contain no inline JS.
// Rules: read data-* only through dataset, write text only through textContent,
// never touch cookies, storage or the hidden anti-forgery form fields.
(function () {
  "use strict";

  // "Select all" / "Clear selection" buttons for checkbox groups.
  document.querySelectorAll("[data-check-group]").forEach((button) => {
    button.addEventListener("click", () => {
      const form = button.closest("form");
      if (!form) return;
      const checked = button.dataset.checkAction === "all";
      form.querySelectorAll('input[type="checkbox"]').forEach((box) => {
        if (box.name === button.dataset.checkGroup) box.checked = checked;
      });
    });
  });

  // Forms that act on the selected checkboxes: block empty submits, confirm the count.
  document.querySelectorAll("form[data-confirm-selected]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const name = form.dataset.confirmSelected;
      let count = 0;
      form.querySelectorAll('input[type="checkbox"]').forEach((box) => {
        if (box.name === name && box.checked) count += 1;
      });
      if (!count) {
        event.preventDefault();
        return;
      }
      const message = (form.dataset.confirmMessage || "Continue for {n} selected?").split("{n}").join(String(count));
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  // Plain confirmations: <form data-confirm="..."> or <button data-confirm="...">.
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
  document.querySelectorAll("button[data-confirm]").forEach((button) => {
    button.addEventListener("click", (event) => {
      if (!window.confirm(button.dataset.confirm)) event.preventDefault();
    });
  });

  // Booking errors that were shown as a popup before: same static message, now from the alert box.
  document.querySelectorAll("[data-popup-message]").forEach((box) => {
    window.alert(box.dataset.popupMessage);
  });

  // Admin cabinet dropdown (<details>): close it on an outside click or Escape.
  document.querySelectorAll("details.cabinet-menu").forEach((menu) => {
    document.addEventListener("click", (event) => {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menu.open) menu.open = false;
    });
  });

  // Booking form: show the chosen service's duration and buffer under the short option label.
  const serviceSelect = document.getElementById("service-select");
  const serviceDetails = document.getElementById("service-details");
  if (serviceSelect && serviceDetails) {
    serviceSelect.addEventListener("change", () => {
      const option = serviceSelect.selectedOptions[0];
      if (!option) return;
      const duration = Number.parseInt(option.dataset.duration || "", 10);
      const buffer = Number.parseInt(option.dataset.buffer || "", 10);
      if (Number.isNaN(duration) || Number.isNaN(buffer)) return;
      serviceDetails.textContent = `Reserved time: ${duration} min + ${buffer} min buffer`;
    });
  }

  // Admin schedule: weekday presets in the bulk work-hours form.
  const bulkWorkHoursForm = document.getElementById("bulk-work-hours-form");
  if (bulkWorkHoursForm) {
    const weekdayCheckboxes = bulkWorkHoursForm.querySelectorAll('input[name="weekdays"]');
    bulkWorkHoursForm.querySelectorAll("[data-weekday-preset]").forEach((button) => {
      button.addEventListener("click", () => {
        const selectedDays = button.dataset.weekdayPreset.split(",").filter(Boolean);
        weekdayCheckboxes.forEach((checkbox) => {
          checkbox.checked = selectedDays.includes(checkbox.value);
        });
      });
    });
  }

  // Admin users: the password confirmation is shown only when creating an administrator.
  const staffRole = document.getElementById("staff-role");
  const adminConfirm = document.getElementById("admin-confirm");
  if (staffRole && adminConfirm) {
    const adminPassword = adminConfirm.querySelector("input");
    const syncAdminConfirm = () => {
      const creatingAdmin = staffRole.value === "admin";
      adminConfirm.hidden = !creatingAdmin;
      if (adminPassword) {
        adminPassword.required = creatingAdmin;
        if (!creatingAdmin) adminPassword.value = "";
      }
    };
    staffRole.addEventListener("change", syncAdminConfirm);
    syncAdminConfirm();
  }

  // Registrar booking: search a patient by email and fill the hidden patient_email fields.
  const patientPicker = document.getElementById("registrar-patient-picker");
  const patientSearch = document.getElementById("registrar-patient-search");
  const patientResults = document.getElementById("registrar-patient-results");
  const patientSelection = document.getElementById("registrar-patient-selection");
  if (patientPicker && patientSearch && patientResults && patientSelection) {
    const bookingButtons = document.querySelectorAll("[data-registrar-book]");
    let searchTimer;
    let searchRequestId = 0;

    const setSelectedPatient = (email, blocked) => {
      document.querySelectorAll('input[name="patient_email"]').forEach((input) => {
        input.value = email || "";
      });
      bookingButtons.forEach((button) => {
        button.disabled = !email || blocked;
      });
      patientSelection.textContent = email
        ? `Selected: ${email} — ${blocked ? "Blocked; booking is disabled." : "Active."}`
        : "Search for a patient and select an active account before booking.";
    };

    const showSearchMessage = (message) => {
      patientResults.replaceChildren();
      const item = document.createElement("li");
      item.textContent = message;
      patientResults.append(item);
    };

    // The preselected email comes from the search field's server-rendered value.
    setSelectedPatient(patientSearch.defaultValue, patientPicker.dataset.selectedBlocked === "true");

    patientSearch.addEventListener("input", () => {
      const query = patientSearch.value.trim();
      setSelectedPatient("", false);
      patientResults.replaceChildren();
      const requestId = ++searchRequestId;
      window.clearTimeout(searchTimer);
      if (query.length < 2) return;

      searchTimer = window.setTimeout(async () => {
        try {
          const response = await fetch(
            `/registrar/patients/search?q=${encodeURIComponent(query)}`,
            { headers: { Accept: "application/json" } }
          );
          if (!response.ok) throw new Error("Patient search failed.");
          const patients = await response.json();
          if (requestId !== searchRequestId) return;
          if (!patients.length) {
            showSearchMessage("No patients found.");
            return;
          }
          patientResults.replaceChildren();
          patients.forEach((patient) => {
            const item = document.createElement("li");
            const button = document.createElement("button");
            button.type = "button";
            button.className = patient.blocked ? "btn btn-sm btn-outline-secondary" : "btn btn-sm btn-outline-primary";
            button.textContent = `${patient.email} — ${patient.blocked ? "Blocked" : "Active"}`;
            button.disabled = patient.blocked;
            button.addEventListener("click", () => {
              patientSearch.value = patient.email;
              patientResults.replaceChildren();
              setSelectedPatient(patient.email, patient.blocked);
            });
            item.append(button);
            patientResults.append(item);
          });
        } catch (error) {
          if (requestId === searchRequestId) {
            showSearchMessage("Could not search patients. Try again.");
          }
        }
      }, 250);
    });
  }
})();
