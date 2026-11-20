/**
 * CyberLens - Interactive Frontend Controller
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Mobile Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.app-sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', function () {
            sidebar.classList.toggle('show');
        });
        // Click outside closes sidebar on mobile
        document.addEventListener('click', function (e) {
            if (window.innerWidth < 992 && sidebar.classList.contains('show')) {
                if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
                    sidebar.classList.remove('show');
                }
            }
        });
    }

    // 2. Initialize Bootstrap Tooltips & Popovers
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // 3. Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            try {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            } catch (e) {}
        }, 5000);
    });

    // 4. Copy-to-clipboard functionality
    document.querySelectorAll('.copy-btn').forEach(function (button) {
        button.addEventListener('click', function () {
            const targetId = button.getAttribute('data-target');
            let textToCopy = '';
            if (targetId) {
                const targetElem = document.getElementById(targetId);
                textToCopy = targetElem ? targetElem.innerText : '';
            } else if (button.getAttribute('data-copy-text')) {
                textToCopy = button.getAttribute('data-copy-text');
            }

            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(function () {
                    const originalHtml = button.innerHTML;
                    button.innerHTML = '<i class="bi bi-check2"></i> Copied!';
                    button.classList.add('btn-success');
                    setTimeout(function () {
                        button.innerHTML = originalHtml;
                        button.classList.remove('btn-success');
                    }, 2000);
                });
            }
        });
    });

    // 5. Findings Live Filter in Scan Detail View
    const findingFilterButtons = document.querySelectorAll('[data-finding-filter]');
    const findingCards = document.querySelectorAll('.finding-card');

    if (findingFilterButtons.length > 0 && findingCards.length > 0) {
        findingFilterButtons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                findingFilterButtons.forEach(b => b.classList.remove('active', 'btn-primary', 'text-white'));
                btn.classList.add('active');

                const filterValue = btn.getAttribute('data-finding-filter');
                let countVisible = 0;

                findingCards.forEach(function (card) {
                    const cardSeverity = card.getAttribute('data-severity');
                    const cardCategory = card.getAttribute('data-category');
                    const cardStatus = card.getAttribute('data-status');

                    let shouldShow = false;
                    if (filterValue === 'all') {
                        shouldShow = true;
                    } else if (filterValue === 'failures') {
                        shouldShow = (cardStatus === 'fail');
                    } else if (filterValue === 'passed') {
                        shouldShow = (cardStatus === 'pass');
                    } else if (filterValue === cardSeverity || filterValue === cardCategory) {
                        shouldShow = true;
                    }

                    if (shouldShow) {
                        card.style.display = 'block';
                        countVisible++;
                    } else {
                        card.style.display = 'none';
                    }
                });

                const countElem = document.getElementById('visibleFindingsCount');
                if (countElem) {
                    countElem.innerText = countVisible;
                }
            });
        });
    }

    // 6. Quick Scan Submission Modal / Banner with Loading State
    const scanForms = document.querySelectorAll('.cyberlens-scan-form');
    scanForms.forEach(function (form) {
        form.addEventListener('submit', function () {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Assessing Posture...';
            }
        });
    });
});
