/**
 * Main JavaScript file for SSL/TLS Security Scanner
 * Handles UI interactions, real-time updates, and form enhancements
 */

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize form validation
    initializeFormValidation();
    
    // Initialize auto-refresh for scan progress
    initializeScanProgressMonitoring();
    
    // Initialize clipboard functionality
    initializeClipboard();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
    
    // Initialize smooth scrolling
    initializeSmoothScrolling();
    
    console.log('SSL Scanner application initialized');
}

/**
 * Initialize Bootstrap tooltips for elements with data-bs-toggle="tooltip"
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Initialize form validation and enhancements
 */
function initializeFormValidation() {
    // Domain hostname validation
    const hostnameInputs = document.querySelectorAll('input[name="hostname"]');
    hostnameInputs.forEach(input => {
        input.addEventListener('input', function() {
            validateHostname(this);
        });
        
        input.addEventListener('blur', function() {
            normalizeHostname(this);
        });
    });
    
    // Bulk domain textarea validation
    const bulkTextarea = document.getElementById('domains_text');
    if (bulkTextarea) {
        bulkTextarea.addEventListener('input', function() {
            validateBulkDomains(this);
        });
    }
    
    // Form submission enhancements
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                // Disable submit button to prevent double submission
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Processing...';
                
                // Re-enable after a delay if form doesn't actually submit
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = submitBtn.getAttribute('data-original-text') || 'Submit';
                }, 3000);
            }
        });
    });
}

/**
 * Validate hostname input
 */
function validateHostname(input) {
    const hostname = input.value.trim();
    const isValid = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(hostname);
    
    if (hostname && !isValid) {
        input.classList.add('is-invalid');
        input.classList.remove('is-valid');
        
        // Add or update error message
        let feedback = input.parentNode.querySelector('.invalid-feedback');
        if (!feedback) {
            feedback = document.createElement('div');
            feedback.className = 'invalid-feedback';
            input.parentNode.appendChild(feedback);
        }
        feedback.textContent = 'Please enter a valid hostname (e.g., example.com)';
    } else if (hostname) {
        input.classList.remove('is-invalid');
        input.classList.add('is-valid');
    } else {
        input.classList.remove('is-invalid', 'is-valid');
    }
}

/**
 * Normalize hostname by removing protocol and trailing slashes
 */
function normalizeHostname(input) {
    let hostname = input.value.trim();
    
    // Remove protocol
    hostname = hostname.replace(/^https?:\/\//, '');
    
    // Remove www. prefix if present
    hostname = hostname.replace(/^www\./, '');
    
    // Remove trailing slash and path
    hostname = hostname.split('/')[0];
    
    // Remove port if present
    hostname = hostname.split(':')[0];
    
    input.value = hostname;
    validateHostname(input);
}

/**
 * Validate bulk domains textarea
 */
function validateBulkDomains(textarea) {
    const domains = textarea.value.split('\n').map(line => line.trim()).filter(line => line);
    let validCount = 0;
    let invalidCount = 0;
    
    domains.forEach(domain => {
        const normalized = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split(':')[0];
        const isValid = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/.test(normalized);
        
        if (isValid) {
            validCount++;
        } else {
            invalidCount++;
        }
    });
    
    // Update helper text
    let helpText = textarea.parentNode.querySelector('.form-text');
    if (!helpText) {
        helpText = document.createElement('div');
        helpText.className = 'form-text';
        textarea.parentNode.appendChild(helpText);
    }
    
    if (domains.length > 0) {
        helpText.innerHTML = `<span class="text-success">${validCount} valid</span> • <span class="text-danger">${invalidCount} invalid</span> domains detected`;
        
        if (invalidCount > 0) {
            textarea.classList.add('is-invalid');
            textarea.classList.remove('is-valid');
        } else {
            textarea.classList.remove('is-invalid');
            textarea.classList.add('is-valid');
        }
    } else {
        helpText.textContent = 'Enter one domain per line. Empty lines will be ignored.';
        textarea.classList.remove('is-invalid', 'is-valid');
    }
}

/**
 * Initialize scan progress monitoring
 */
function initializeScanProgressMonitoring() {
    // Check if we're on a page that should monitor scan progress
    const progressBar = document.getElementById('scanProgress');
    if (!progressBar) return;
    
    // Start monitoring if scan is in progress
    monitorScanProgress();
}

/**
 * Monitor scan progress and update UI
 */
function monitorScanProgress() {
    const progressBar = document.getElementById('scanProgress');
    const completedCount = document.getElementById('completedCount');
    const failedCount = document.getElementById('failedCount');
    const remainingCount = document.getElementById('remainingCount');
    
    if (!progressBar) return;
    
    // Check scan status every 2 seconds
    const checkInterval = setInterval(() => {
        fetch('/api/scan_status')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'running') {
                    // Update progress bar
                    const progress = Math.round(data.progress * 10) / 10; // Round to 1 decimal
                    progressBar.style.width = progress + '%';
                    progressBar.textContent = progress + '%';
                    progressBar.setAttribute('aria-valuenow', progress);
                    
                    // Update counters
                    if (completedCount) completedCount.textContent = data.completed;
                    if (failedCount) failedCount.textContent = data.failed;
                    if (remainingCount) remainingCount.textContent = data.total - data.completed - data.failed;
                    
                    // Update page title with progress
                    document.title = `(${progress}%) SSL/TLS Security Scanner`;
                } else {
                    // Scan completed or not running
                    clearInterval(checkInterval);
                    
                    // Reset page title
                    document.title = 'SSL/TLS Security Scanner';
                    
                    // If scan just completed, show notification and reload
                    if (data.status === 'completed') {
                        showNotification('Scan completed successfully!', 'success');
                        setTimeout(() => {
                            window.location.reload();
                        }, 2000);
                    } else if (data.status === 'failed') {
                        showNotification('Scan failed. Please check the logs.', 'danger');
                    }
                }
            })
            .catch(error => {
                console.error('Error checking scan status:', error);
                // Continue trying but less frequently
                setTimeout(() => {
                    monitorScanProgress();
                }, 10000);
                clearInterval(checkInterval);
            });
    }, 2000);
}

/**
 * Show notification toast
 */
function showNotification(message, type = 'info') {
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        toastContainer.style.zIndex = '9999';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toastHtml = `
        <div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
                <div class="toast-body">
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    // Initialize and show toast
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: 5000
    });
    
    toast.show();
    
    // Remove toast element after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

/**
 * Initialize clipboard functionality
 */
function initializeClipboard() {
    // Add copy buttons to code blocks and pre elements
    const codeBlocks = document.querySelectorAll('pre, code');
    codeBlocks.forEach(block => {
        if (block.textContent.length > 20) { // Only add copy button to longer code blocks
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm btn-outline-secondary position-absolute top-0 end-0 m-2';
            copyBtn.innerHTML = '<i data-feather="copy" width="14" height="14"></i>';
            copyBtn.title = 'Copy to clipboard';
            
            // Make parent relative if it isn't already
            const parent = block.parentElement;
            if (getComputedStyle(parent).position === 'static') {
                parent.style.position = 'relative';
            }
            
            parent.appendChild(copyBtn);
            
            copyBtn.addEventListener('click', function() {
                copyToClipboard(block.textContent);
                copyBtn.innerHTML = '<i data-feather="check" width="14" height="14"></i>';
                copyBtn.classList.replace('btn-outline-secondary', 'btn-success');
                
                setTimeout(() => {
                    copyBtn.innerHTML = '<i data-feather="copy" width="14" height="14"></i>';
                    copyBtn.classList.replace('btn-success', 'btn-outline-secondary');
                    feather.replace(); // Re-initialize feather icons
                }, 2000);
            });
        }
    });
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Failed to copy: ', err);
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

/**
 * Fallback clipboard copy for older browsers
 */
function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('Copied to clipboard!', 'success');
    } catch (err) {
        console.error('Fallback copy failed: ', err);
        showNotification('Failed to copy to clipboard', 'warning');
    }
    
    document.body.removeChild(textArea);
}

/**
 * Initialize keyboard shortcuts
 */
function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + K: Focus search (if search exists)
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('input[type="search"], input[name="search"]');
            if (searchInput) {
                searchInput.focus();
            }
        }
        
        // Ctrl/Cmd + Enter: Submit focused form
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const activeElement = document.activeElement;
            if (activeElement && (activeElement.tagName === 'INPUT' || activeElement.tagName === 'TEXTAREA')) {
                const form = activeElement.closest('form');
                if (form) {
                    e.preventDefault();
                    form.submit();
                }
            }
        }
        
        // Escape: Close modals
        if (e.key === 'Escape') {
            const openModals = document.querySelectorAll('.modal.show');
            openModals.forEach(modal => {
                const modalInstance = bootstrap.Modal.getInstance(modal);
                if (modalInstance) {
                    modalInstance.hide();
                }
            });
        }
    });
}

/**
 * Initialize smooth scrolling for anchor links
 */
function initializeSmoothScrolling() {
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                e.preventDefault();
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

/**
 * Utility function to format bytes
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Utility function to format time ago
 */
function timeAgo(date) {
    const now = new Date();
    const secondsPast = (now.getTime() - date.getTime()) / 1000;
    
    if (secondsPast < 60) {
        return parseInt(secondsPast) + ' seconds ago';
    }
    if (secondsPast < 3600) {
        return parseInt(secondsPast / 60) + ' minutes ago';
    }
    if (secondsPast <= 86400) {
        return parseInt(secondsPast / 3600) + ' hours ago';
    }
    if (secondsPast <= 2592000) {
        return parseInt(secondsPast / 86400) + ' days ago';
    }
    if (secondsPast <= 31536000) {
        return parseInt(secondsPast / 2592000) + ' months ago';
    }
    return parseInt(secondsPast / 31536000) + ' years ago';
}

/**
 * Utility function to debounce function calls
 */
function debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction() {
        const context = this;
        const args = arguments;
        
        const later = function() {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        
        if (callNow) func.apply(context, args);
    };
}

/**
 * Utility function to throttle function calls
 */
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Enhanced table functionality
 */
function initializeTableEnhancements() {
    // Add sorting functionality to tables with sortable class
    const sortableTables = document.querySelectorAll('.table-sortable');
    sortableTables.forEach(table => {
        const headers = table.querySelectorAll('th[data-sort]');
        headers.forEach(header => {
            header.style.cursor = 'pointer';
            header.innerHTML += ' <i data-feather="chevrons-up-down" width="12" height="12"></i>';
            
            header.addEventListener('click', function() {
                const sortKey = this.getAttribute('data-sort');
                const sortDir = this.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';
                this.setAttribute('data-sort-dir', sortDir);
                
                sortTable(table, sortKey, sortDir);
            });
        });
    });
}

/**
 * Sort table by column
 */
function sortTable(table, sortKey, sortDir) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    
    rows.sort((a, b) => {
        const aVal = a.querySelector(`[data-sort-value="${sortKey}"]`)?.textContent || 
                     a.querySelector(`td:nth-child(${getColumnIndex(table, sortKey)})`)?.textContent || '';
        const bVal = b.querySelector(`[data-sort-value="${sortKey}"]`)?.textContent || 
                     b.querySelector(`td:nth-child(${getColumnIndex(table, sortKey)})`)?.textContent || '';
        
        // Try to parse as numbers first
        const aNum = parseFloat(aVal);
        const bNum = parseFloat(bVal);
        
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return sortDir === 'asc' ? aNum - bNum : bNum - aNum;
        }
        
        // Fall back to string comparison
        return sortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
    
    // Re-append sorted rows
    rows.forEach(row => tbody.appendChild(row));
    
    // Update sort indicators
    const headers = table.querySelectorAll('th[data-sort]');
    headers.forEach(header => {
        const icon = header.querySelector('[data-feather]');
        if (header.getAttribute('data-sort') === sortKey) {
            icon.setAttribute('data-feather', sortDir === 'asc' ? 'chevron-up' : 'chevron-down');
        } else {
            icon.setAttribute('data-feather', 'chevrons-up-down');
        }
    });
    
    // Re-initialize feather icons
    feather.replace();
}

/**
 * Get column index for sorting
 */
function getColumnIndex(table, sortKey) {
    const headers = table.querySelectorAll('th');
    for (let i = 0; i < headers.length; i++) {
        if (headers[i].getAttribute('data-sort') === sortKey) {
            return i + 1;
        }
    }
    return 1;
}

// Export functions for global access if needed
window.SSLScanner = {
    showNotification,
    copyToClipboard,
    formatBytes,
    timeAgo,
    debounce,
    throttle
};

// Auto-initialize table enhancements when content is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeTableEnhancements();
});

// Handle page visibility changes to pause/resume monitoring
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
        // Page became visible, resume monitoring if needed
        const progressBar = document.getElementById('scanProgress');
        if (progressBar) {
            setTimeout(monitorScanProgress, 1000);
        }
    }
});

// Service worker registration for offline support (if needed in future)
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        // Uncomment if you add a service worker
        // navigator.serviceWorker.register('/sw.js').then(function(registration) {
        //     console.log('ServiceWorker registration successful');
        // }).catch(function(err) {
        //     console.log('ServiceWorker registration failed: ', err);
        // });
    });
}
