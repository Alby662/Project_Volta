// common.js (updated with improved report type selection)
window.onload = () => {
  const btn = document.getElementById("btnSave");
  if (!btn) return;

  // Report type list (15 items: 12 fixed + 3 extras).
  const folderOptions = [
    { key: "liquid_ir", label: "Liquid IR" },                     // 1
    { key: "draining_dry_ir", label: "Draining & Dry IR" },       // 2
    { key: "final_dimension_ir", label: "Final Dimension IR" },  // 3
    { key: "hydrostatic_ir", label: "Hydrostatic IR" },          // 4
    { key: "penetrating_oil_ir", label: "Penetrating Oil IR" },  // 5 (Oil Leak)
    { key: "pickling_pass_ir", label: "Pickling & Pass IR" },    // 6
    { key: "raw_material_ir", label: "Raw Material IR" },        // 7
    { key: "rf_pad_ir", label: "RF Pad IR" },                    // 8 (RF-PAD Pneumatic)
    { key: "stage_ir", label: "Stage IR" },                      // 9
    { key: "surface_prep_paint_ir", label: "Surface Prep & Paint IR" }, // 10
    { key: "vacuum_ir", label: "Vacuum IR" },                    // 11
    { key: "visual_exam_ir", label: "Visual Exam IR" },          // 12
    { key: "extra1", label: "Extra Report 1" },                  // 13
    { key: "extra2", label: "Extra Report 2" },                  // 14
    { key: "extra3", label: "Extra Report 3" }                   // 15
  ];

  // Create report type dropdown if it doesn't exist
  function createReportTypeDropdown() {
    // Check if dropdown already exists
    if (document.getElementById("reportTypeDropdown")) return;
    
    // Create dropdown element
    const select = document.createElement("select");
    select.id = "reportTypeDropdown";
    select.style.cssText = "margin: 10px 0; padding: 8px; width: 100%;";
    
    // Add default option
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "Select Report Type";
    select.appendChild(defaultOption);
    
    // Add all options
    folderOptions.forEach((option, index) => {
      const opt = document.createElement("option");
      opt.value = option.key;
      opt.textContent = `${index + 1}. ${option.label}`;
      select.appendChild(opt);
    });
    
    // Auto-select the report type based on the current URL path
    const path = window.location.pathname;
    const pathParts = path.split('/');
    const reportTypeFromPath = pathParts[pathParts.length - 1];
    
    // Map URL paths to report type keys
    const pathToKeyMap = {
      'liquid': 'liquid_ir',
      'vacuum': 'vacuum_ir',
      'draining_dry': 'draining_dry_ir',
      'final_dimension': 'final_dimension_ir',
      'hydrostatic_test': 'hydrostatic_ir',
      'oil_leak': 'penetrating_oil_ir',
      'pickling_passivation': 'pickling_pass_ir',
      'raw_material': 'raw_material_ir',
      'rf_pad_pneumatic': 'rf_pad_ir',
      'surface_preparation_painting': 'surface_prep_paint_ir',
      'visual_examination': 'visual_exam_ir'
    };
    
    const autoSelectedKey = pathToKeyMap[reportTypeFromPath];
    if (autoSelectedKey) {
      select.value = autoSelectedKey;
    }
    
    // Insert dropdown before the save button
    btn.parentNode.insertBefore(select, btn);
  }

  // Get selected report type
  function getSelectedReportType() {
    const dropdown = document.getElementById("reportTypeDropdown");
    if (dropdown && dropdown.value) {
      const selectedIndex = folderOptions.findIndex(opt => opt.key === dropdown.value);
      if (selectedIndex !== -1) {
        return {
          key: folderOptions[selectedIndex].key,
          folder: selectedIndex + 1,
          label: folderOptions[selectedIndex].label
        };
      }
    }
    return null;
  }

  // Create the dropdown when page loads
  createReportTypeDropdown();

  // Improved error display function
  function showError(message) {
    // Try to show error in a dedicated error div first
    const errorDiv = document.getElementById("error-message");
    if (errorDiv) {
      errorDiv.textContent = message;
      errorDiv.style.display = "block";
      // Hide error after 5 seconds
      setTimeout(() => {
        errorDiv.style.display = "none";
      }, 5000);
    } else {
      // Fallback to alert
      alert("❌ Error: " + message);
    }
  }

  // Improved success display function
  function showSuccess(message) {
    // Try to show success in a dedicated success div first
    const successDiv = document.getElementById("success-message");
    if (successDiv) {
      successDiv.textContent = message;
      successDiv.style.display = "block";
      // Hide success after 3 seconds
      setTimeout(() => {
        successDiv.style.display = "none";
      }, 3000);
    } else {
      // Fallback to alert
      alert("✅ Success: " + message);
    }
  }

  btn.addEventListener("click", async () => {
    try {
      // Make form fields static for accurate PDF capture
      document.querySelectorAll("input, textarea, select").forEach(el => {
        const tag = el.tagName.toLowerCase();

        if (tag === "textarea") {
          el.innerHTML = el.value;
          el.setAttribute("readonly", "readonly");
        }

        if (tag === "select") {
          Array.from(el.options).forEach(option => {
            if (option.selected) option.setAttribute("selected", "selected");
            else option.removeAttribute("selected");
          });
          el.setAttribute("disabled", "disabled");
        }

        if (tag === "input") {
          el.setAttribute("value", el.value);
          if (el.type !== "checkbox" && el.type !== "radio") {
            el.setAttribute("readonly", "readonly");
            el.setAttribute("disabled", "disabled");
          }
        }
      });

      const html = document.documentElement.outerHTML;
      const reportTypeFromTitle = document.title && document.title.trim();
      const reportTypeName = reportTypeFromTitle || prompt("Enter report title:");
      
      // Extract form data including logo selection
      const formData = {};
      
      // Extract all input values
      document.querySelectorAll("input").forEach(input => {
        if (input.name) {
          if (input.type === 'checkbox' || input.type === 'radio') {
            formData[input.name] = input.checked;
          } else {
            formData[input.name] = input.value;
          }
        }
      });
      
      // Extract all select values
      document.querySelectorAll("select").forEach(select => {
        if (select.name) {
          formData[select.name] = select.value;
        }
      });
      
      // Extract all textarea values
      document.querySelectorAll("textarea").forEach(textarea => {
        if (textarea.name) {
          formData[textarea.name] = textarea.value;
        }
      });
      
      // Use sessionStorage instead of localStorage for better security
      const token = sessionStorage.getItem("adminToken");

      // Get selection from dropdown
      const selection = getSelectedReportType();
      if (!selection) {
        showError("Please select a report type from the dropdown. This should be automatically selected based on your template, but if it isn't, please select the correct report type.");
        return;
      }

      // selection.folder is the numeric folder (1..15)
      // selection.key is the reportType key (e.g., 'liquid_ir')
      const { folder, key: reportType } = selection;

      if (!html || !reportTypeName) {
        showError("Missing HTML or report title");
        return;
      }
      
      if (!token) {
        showError("You're not logged in");
        window.location.href = "/admin";
        return;
      }

      // Show loading indicator
      const originalBtnText = btn.textContent;
      btn.textContent = "Saving...";
      btn.disabled = true;

      const res = await fetch("/api/save-report", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + token
        },
        body: JSON.stringify({ html, reportType, folder, reportTitle: reportTypeName, formData }) // include both reportType key and folder
      });

      const data = await res.json();
      
      // Restore button
      btn.textContent = originalBtnText;
      btn.disabled = false;

      if (res.ok && data.fileId) {
        showSuccess("Report saved to server");
        if (data.fromCache) {
          showSuccess("Report was served from cache for faster processing");
        }
        window.open("/get-pdf/" + data.fileId, "_blank");
      } else {
        showError("Upload failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      // Restore button
      const btn = document.getElementById("btnSave");
      if (btn) {
        btn.textContent = "Save Report";
        btn.disabled = false;
      }
      showError("Network error: " + err.message);
    }
  });
};