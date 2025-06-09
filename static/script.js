// static/script.js

// Navigation functionality (already provided by user)
const navItems = document.querySelectorAll('.nav-item');
const menuToggle = document.querySelector('.menu-toggle');
const sidebar = document.querySelector('.sidebar');

navItems.forEach(item => {
    item.addEventListener('click', () => {
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
    });
});

// Mobile menu toggle (already provided by user)
menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('active');
});

// Close sidebar when clicking outside on mobile (already provided by user)
document.addEventListener('click', (e) => {
    if (window.innerWidth <= 768) {
        if (!sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
            sidebar.classList.remove('active');
        }
    }
});

// Animate progress bars on load (already provided by user)
window.addEventListener('load', () => {
    const progressBars = document.querySelectorAll('.progress-fill');
    progressBars.forEach(bar => {
        const width = bar.style.width;
        bar.style.width = '0%';
        setTimeout(() => {
            bar.style.width = width;
        }, 500);
    });
});

// --- Dynamic Data Integration for Charts (from Flask) ---
// This part replaces the hardcoded data you had in the HTML for charts.
// The data will be passed from Flask using Jinja2 and converted from JSON.

// Get chart data from hidden elements or directly from global variables (preferred for simplicity here)
// Flask will render these variables into the HTML directly in the script tags.
// Example: <script> var attackChartLabels = JSON.parse('{{ attack_chart_labels | safe }}'); </script>
// These vars will be declared in the HTML directly.

// Chart.js configuration for "Total Attacks Over Time" (replacing activityChart)
const ctxAttacks = document.getElementById('attacksOverTimeChart');
if (ctxAttacks) { // Check if canvas exists
    const attackLabels = JSON.parse(ctxAttacks.dataset.labels); // Data from data-attributes
    const attackData = JSON.parse(ctxAttacks.dataset.data);

    new Chart(ctxAttacks, {
        type: 'line',
        data: {
            labels: attackLabels,
            datasets: [{
                label: 'Attacks',
                data: attackData,
                borderColor: '#4a9eff',
                backgroundColor: 'rgba(74, 158, 255, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: { // Chart.js v3+ uses 'x' and 'y' instead of xAxes/yAxes
                    type: 'time',
                    time: {
                        unit: 'hour',
                        displayFormats: {
                            hour: 'MMM DD HH:mm'
                        },
                        tooltipFormat: 'YYYY-MM-DD HH:mm'
                    },
                    grid: {
                        color: '#444'
                    },
                    ticks: {
                        color: '#888'
                    }
                },
                y: {
                    grid: {
                        color: '#444'
                    },
                    ticks: {
                        color: '#888',
                        beginAtZero: true
                    }
                }
            }
        }
    });
}


// Chart.js configuration for "Top 5 Source IP Addresses" (new chart)
const ctxTopIPs = document.getElementById('topIPsChart');
if (ctxTopIPs) { // Check if canvas exists
    const topIpLabels = JSON.parse(ctxTopIPs.dataset.labels); // Data from data-attributes
    const topIpCounts = JSON.parse(ctxTopIPs.dataset.data);

    new Chart(ctxTopIPs, {
        type: 'horizontalBar', // Use 'bar' type with indexAxis: 'y' for Chart.js v3+
        data: {
            labels: topIpLabels,
            datasets: [{
                label: 'Number of Attacks',
                data: topIpCounts,
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)', // Red
                    'rgba(54, 162, 235, 0.7)', // Blue
                    'rgba(255, 206, 86, 0.7)', // Yellow
                    'rgba(75, 192, 192, 0.7)', // Green
                    'rgba(153, 102, 255, 0.7)' // Purple
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: {
                        beginAtZero: true,
                        color: '#888'
                    },
                    grid: {
                        color: '#444'
                    }
                },
                y: {
                    ticks: {
                        color: '#888'
                    },
                    grid: {
                        color: '#444'
                    }
                }
            }
        }
    });
}

// --- Simulate real-time data updates (OPTIONAL - for client-side demo, not needed with Flask dynamic data) ---
// If you want this to continue simulating client-side updates (independent of Flask reloads)
// you can keep it. Otherwise, comment it out. Your Flask data is refreshed on page load.
// function updateStats() {
//     const interactions = document.querySelector('.stat-card:nth-child(1) .stat-number');
//     const uniqueIPs = document.querySelector('.stat-card:nth-child(2) .stat-number');
//     const alerts = document.querySelector('.stat-card:nth-child(3) .stat-number');

//     if (Math.random() > 0.7) {
//         const currentInteractions = parseInt(interactions.textContent.replace(',', ''));
//         interactions.textContent = (currentInteractions + Math.floor(Math.random() * 5) + 1).toLocaleString();
//     }

//     if (Math.random() > 0.8) {
//         const currentIPs = parseInt(uniqueIPs.textContent);
//         uniqueIPs.textContent = currentIPs + Math.floor(Math.random() * 3) + 1;
//     }

//     if (Math.random() > 0.9) {
//         const currentAlerts = parseInt(alerts.textContent);
//         alerts.textContent = currentAlerts + Math.floor(Math.random() * 2) + 1;
//     }
// }
// setInterval(updateStats, 30000);