/* Shared interactions for non-landing application pages. */
document.addEventListener('DOMContentLoaded', () => {
  const accountType = document.getElementById('account_type');
  const studentFields = document.getElementById('studentFields');

  if (accountType && studentFields) {
    const updateStudentFields = () => {
      studentFields.style.display = accountType.value === 'student' ? 'block' : 'none';
    };
    accountType.addEventListener('change', updateStudentFields);
    updateStudentFields();
  }

  const progressPage = document.querySelector('.scan-progress-page');
  if (progressPage) {
    const scanId = progressPage.dataset.scanId;
    const pollStatus = async () => {
      try {
        const response = await fetch(`/scans/${scanId}/status`);
        const data = await response.json();
        if (data.status === 'completed' && data.result_url) {
          window.location.href = data.result_url;
          return;
        }
        if (data.status === 'failed') {
          document.getElementById('statusText').innerText = `Failed: ${data.error || 'Unknown error'}`;
          return;
        }
        window.setTimeout(pollStatus, 1500);
      } catch {
        window.setTimeout(pollStatus, 2500);
      }
    };
    window.setTimeout(pollStatus, 1000);
  }

  const resultsHeader = document.querySelector('[data-base-score]');
  const simulator = document.querySelector('.simulator-box');
  if (resultsHeader && simulator) {
    const baseScore = Number(resultsHeader.dataset.baseScore);
    const updateSimulator = () => {
      let pointsRecovered = 0;
      let selectedCount = 0;
      document.querySelectorAll('.sim-checkbox').forEach((checkbox) => {
        if (checkbox.checked) {
          selectedCount += 1;
          pointsRecovered += Number.parseInt(checkbox.dataset.impact || '0', 10);
        }
      });
      document.getElementById('simulatedScore').innerText = Math.min(100, baseScore + pointsRecovered);
      document.getElementById('simSelectedCount').innerText = selectedCount;
      document.getElementById('simPointsRecovered').innerText = `+${pointsRecovered} pts`;
    };
    document.querySelectorAll('.sim-checkbox').forEach((checkbox) => {
      checkbox.addEventListener('change', updateSimulator);
    });
  }

  document.querySelectorAll('.comparison-select').forEach((select) => {
    select.addEventListener('change', () => select.form.submit());
  });

  document.querySelectorAll('.delete-application-form').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm('Delete this target application and all its scan history?')) {
        event.preventDefault();
      }
    });
  });
});
