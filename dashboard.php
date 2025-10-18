<?php
require_once 'db.php';
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: signin.php');
    exit();
}

// Fetch user data from database
$user_id = $_SESSION['user_id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    // If user not found, redirect to signin
    session_destroy();
    header('Location: signin.php');
    exit();
}

// Get user's full name
$user_name = $user['first_name'] . ' ' . $user['last_name'];

// Fetch order statistics
$total_orders = 0;
$pending_orders = 0;

try {
    // Get total orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM orders WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $total_orders = $result['count'] ?? 0;

    // Get pending orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM orders WHERE user_id = ? AND status = 'pending'");
    $stmt->execute([$user_id]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $pending_orders = $result['count'] ?? 0;
} catch (Exception $e) {
    error_log("Error fetching orders: " . $e->getMessage());
}

// Format phone number for Philippine format
function formatPhilippinePhone($phone)
{
    if (empty($phone) || $phone == '-') {
        return '-';
    }

    // Remove any non-digit characters
    $clean_phone = preg_replace('/[^0-9]/', '', $phone);

    // If it starts with 63 (country code without +)
    if (substr($clean_phone, 0, 2) === '63' && strlen($clean_phone) === 12) {
        return '+63' . substr($clean_phone, 2);
    }
    // If it starts with 0 and has 10 digits after (09XXXXXXXXX)
    elseif (substr($clean_phone, 0, 1) === '0' && strlen($clean_phone) === 11) {
        return '+63' . substr($clean_phone, 1);
    }
    // If it's already 10 digits without 0 (9XXXXXXXXX)
    elseif (strlen($clean_phone) === 10 && substr($clean_phone, 0, 1) === '9') {
        return '+63' . $clean_phone;
    }
    // If it's already in +63 format
    elseif (substr($clean_phone, 0, 2) === '63' && strlen($clean_phone) === 12) {
        return '+' . $clean_phone;
    }
    // For any other format, return as is
    else {
        return $phone;
    }
}

$formatted_phone = formatPhilippinePhone($user['phone'] ?? '');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard - University Canteen Kiosk</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #eb6c1eff;
            --primary-light: #ff8c3a;
            --primary-dark: #53545cff;
            --secondary: #6c757d;
            --dark: #1d2a3a;
            --light: #f8f9fa;
            --light-gray: #e9ecef;
            --border: #dee2e6;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
            --shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            --radius: 8px;
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', sans-serif;
        }

        body {
            background: #f8fafc;
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .dashboard-container {
            display: flex;
            flex: 1;
        }

        /* Sidebar Styles */
        .sidebar {
            width: 250px;
            background: var(--dark);
            color: white;
            padding: 20px 0;
            display: flex;
            flex-direction: column;
        }

        .sidebar-header {
            padding: 0 20px 20px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 20px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: var(--primary);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
        }

        .logo-text {
            font-size: 1.2rem;
            font-weight: 700;
        }

            .logo-text .canteen {
                color: var(--primary-light);
            }

            .logo-text .kiosk {
                color: white;
            }

        .sidebar-nav {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        .nav-item {
            padding: 12px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            transition: var(--transition);
        }

            .nav-item:hover, .nav-item.active {
                background: rgba(255,255,255,0.1);
                color: white;
            }

            .nav-item i {
                width: 20px;
                text-align: center;
            }

        .sidebar-footer {
            padding: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
            margin-top: auto;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }

            .user-info img {
                width: 40px;
                height: 40px;
                border-radius: 50%;
                object-fit: cover;
                border: 2px solid var(--primary);
            }

        .user-details {
            flex: 1;
            overflow: hidden;
        }

        .user-name {
            font-weight: 600;
            font-size: 0.9rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: white;
        }

        .user-role {
            font-size: 0.8rem;
            opacity: 0.7;
            color: white;
        }

        .logout-btn {
            display: block;
            width: 100%;
            padding: 10px;
            background: rgba(255,255,255,0.1);
            color: white;
            text-align: center;
            border-radius: var(--radius);
            text-decoration: none;
            transition: var(--transition);
            cursor: pointer;
            border: none;
            font-size: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 10px;
        }

            .logout-btn:hover {
                background: var(--primary);
            }

        /* Main Content */
        .main-content {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }

        .page-title {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .welcome-text {
            color: var(--secondary);
            margin-top: 5px;
        }

        .date-display {
            background: white;
            padding: 10px 15px;
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }

        .stat-card {
            background: white;
            border-radius: var(--radius);
            padding: 20px;
            box-shadow: var(--shadow);
            display: flex;
            align-items: center;
            transition: var(--transition);
        }

            .stat-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            margin-right: 15px;
            flex-shrink: 0;
        }

        .stat-orders {
            background: rgba(235, 108, 30, 0.15);
            color: var(--primary);
        }

        .stat-pending {
            background: rgba(255, 193, 7, 0.15);
            color: var(--warning);
        }

        .stat-info h3 {
            font-size: 1.8rem;
            margin-bottom: 5px;
            font-weight: 700;
        }

        .stat-info p {
            color: var(--secondary);
            font-size: 0.9rem;
        }

        /* Dashboard Content */
        .dashboard-content {
            background: white;
            border-radius: var(--radius);
            padding: 25px;
            box-shadow: var(--shadow);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--light-gray);
        }

        .card-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Profile Info */
        .profile-info {
            display: grid;
            gap: 15px;
        }

        .profile-item {
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--light-gray);
        }

            .profile-item:last-child {
                border-bottom: none;
            }

        .profile-label {
            font-weight: 500;
            color: var(--secondary);
            flex: 1;
        }

        .profile-value {
            font-weight: 600;
            color: var(--dark);
            text-align: right;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* Logout Modal */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background-color: white;
            border-radius: var(--radius);
            padding: 25px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.2);
            text-align: center;
        }

        .modal-icon {
            font-size: 3rem;
            color: var(--primary);
            margin-bottom: 15px;
        }

        .modal-title {
            font-size: 1.5rem;
            margin-bottom: 10px;
            color: var(--dark);
            font-weight: 600;
        }

        .modal-message {
            margin-bottom: 20px;
            color: var(--secondary);
            line-height: 1.5;
        }

        .modal-buttons {
            display: flex;
            gap: 10px;
            justify-content: center;
        }

        .modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            transition: var(--transition);
            min-width: 100px;
        }

        .modal-btn-confirm {
            background-color: var(--primary);
            color: white;
        }

            .modal-btn-confirm:hover {
                background-color: var(--primary-dark);
            }

        .modal-btn-cancel {
            background-color: var(--light-gray);
            color: var(--dark);
            border: 1px solid var(--border);
        }

            .modal-btn-cancel:hover {
                background-color: var(--border);
            }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .sidebar {
                width: 200px;
            }
        }

        @media (max-width: 768px) {
            .dashboard-container {
                flex-direction: column;
            }

            .sidebar {
                width: 100%;
                padding: 10px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .sidebar-nav {
                flex-direction: row;
                overflow-x: auto;
                gap: 5px;
                margin-bottom: 10px;
            }

            .nav-item {
                padding: 10px;
                white-space: nowrap;
            }

                .nav-item span {
                    display: none;
                }

            .header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .profile-item {
                flex-direction: column;
                gap: 5px;
            }
            
            .profile-value {
                text-align: left;
            }
        }

        @media (max-width: 480px) {
            .main-content {
                padding: 15px;
            }
            
            .stats-grid {
                gap: 15px;
            }
            
            .stat-card {
                padding: 15px;
            }
            
            .stat-icon {
                width: 50px;
                height: 50px;
                font-size: 1.2rem;
                margin-right: 12px;
            }
            
            .stat-info h3 {
                font-size: 1.5rem;
            }
            
            .dashboard-content {
                padding: 20px;
            }
            
            .card-title {
                font-size: 1.2rem;
            }
        }
    </style>
</head>
<body>
    <!-- Logout Confirmation Modal -->
    <div id="logoutModal" class="modal">
        <div class="modal-content">
            <div class="modal-icon">
                <i class="fas fa-sign-out-alt"></i>
            </div>
            <h2 class="modal-title">Confirm Logout</h2>
            <p class="modal-message">Are you sure you want to logout from Canteen Kiosk?</p>
            <div class="modal-buttons">
                <button class="modal-btn modal-btn-confirm" onclick="performLogout()">Yes, Logout</button>
                <button class="modal-btn modal-btn-cancel" onclick="closeModal()">Cancel</button>
            </div>
        </div>
    </div>

    <div class="dashboard-container">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <div class="logo-icon">
                        <i class="fas fa-utensils"></i>
                    </div>
                    <div class="logo-text"><span class="canteen">CANTEEN</span><span class="kiosk">KIOSK</span></div>
                </div>
            </div>

            <nav class="sidebar-nav">
                <a href="dashboard.php" class="nav-item active">
                    <i class="fas fa-home"></i>
                    <span>Dashboard</span>
                </a>
                <a href="menu_order.php" class="nav-item">
                    <i class="fas fa-utensils"></i>
                    <span>Menu & Order</span>
                </a>
                <a href="order_history.php" class="nav-item">
                    <i class="fas fa-history"></i>
                    <span>Order History</span>
                </a>
            </nav>

            <div class="sidebar-footer">
                <div class="user-info">
                    <img id="user-avatar" src="https://ui-avatars.com/api/?name=<?php echo urlencode($user_name); ?>&background=eb6c1e&color=fff" alt="User Avatar">
                    <div class="user-details">
                        <div id="user-name" class="user-name"><?php echo htmlspecialchars($user_name); ?></div>
                        <div id="user-role" class="user-role">
                            <?php
                            $teaching_rank = $user['teaching_rank'] ?? '';
                            $rank_display = [
                                'instructor' => 'Instructor',
                                'assistant' => 'Assistant Professor',
                                'associate' => 'Associate Professor',
                                'professor' => 'Professor',
                                'university_professor' => 'University Professor'
                            ];
                            echo $rank_display[$teaching_rank] ?? 'User';
                            ?>
                        </div>
                    </div>
                </div>

                <button class="logout-btn" onclick="showLogoutModal()">
                    <i class="fas fa-sign-out-alt"></i> Log Out
                </button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Dashboard View -->
            <div id="dashboard-view">
                <div class="header">
                    <div>
                        <h1 class="page-title">
                            <i class="fas fa-home"></i> Dashboard
                        </h1>
                        <p id="welcome-text" class="welcome-text">Welcome back, <?php echo htmlspecialchars($user['first_name']); ?>!</p>
                    </div>
                    <div class="date-display">
                        <i class="fas fa-calendar-day"></i> <span id="current-date"></span>
                    </div>
                </div>

                <!-- User Information Card -->
                <div class="dashboard-content">
                    <div class="card-header">
                        <h2 class="card-title">
                            <i class="fas fa-user-circle"></i> User Information
                        </h2>
                    </div>
                    <div class="profile-info">
                        <div class="profile-item">
                            <span class="profile-label">Full Name:</span>
                            <span id="user-name" class="profile-value"><?php echo htmlspecialchars($user_name); ?></span>
                        </div>
                        <div class="profile-item">
                            <span class="profile-label">User ID:</span>
                            <span id="user-id" class="profile-value"><?php echo htmlspecialchars($user['user_id']); ?></span>
                        </div>
                        <div class="profile-item">
                            <span class="profile-label">College/Department:</span>
                            <span id="user-college" class="profile-value"><?php echo htmlspecialchars($user['college']); ?></span>
                        </div>
                        <div class="profile-item">
                            <span class="profile-label">Teaching Rank:</span>
                            <span id="user-rank" class="profile-value">
                                <?php
                                echo $rank_display[$teaching_rank] ?? 'Not specified';
                                ?>
                            </span>
                        </div>
                        <div class="profile-item">
                            <span class="profile-label">Email Address:</span>
                            <span id="user-email" class="profile-value"><?php echo htmlspecialchars($user['email']); ?></span>
                        </div>
                        <div class="profile-item">
                            <span class="profile-label">Phone Number:</span>
                            <span id="user-phone" class="profile-value"><?php echo htmlspecialchars($formatted_phone); ?></span>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        // Set current date
        const now = new Date();
        const options = { year: 'numeric', month: 'long', day: 'numeric' };
        document.getElementById('current-date').textContent = now.toLocaleDateString('en-US', options);

        // Show logout confirmation modal
        function showLogoutModal() {
            document.getElementById('logoutModal').style.display = 'flex';
        }

        // Close modal
        function closeModal() {
            document.getElementById('logoutModal').style.display = 'none';
        }

        // Perform logout action - redirect to signin.php
        function performLogout() {
            // Redirect to the signout page
            window.location.href = "signout.php";
        }

        // Close modal if user clicks outside the modal content
        window.onclick = function(event) {
            const modal = document.getElementById('logoutModal');
            if (event.target === modal) {
                closeModal();
            }
        };
    </script>
</body>
</html>