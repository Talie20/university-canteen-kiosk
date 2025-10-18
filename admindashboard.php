<?php
require_once 'db.php';
session_start();

// Redirect if not logged in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: adminsignin.php');
    exit();
}

// Get admin information from session
$admin_id = $_SESSION['admin_id'];
$admin_username = $_SESSION['admin_username'];
$admin_role = $_SESSION['admin_role'];
$admin_full_name = $_SESSION['admin_full_name'];

// Initialize error variable
$update_error = null;

// Process order status updates
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_order_status'])) {
        $order_id = $_POST['order_id'];
        $new_status = $_POST['status'];
        $notify_customer = isset($_POST['notify_customer']) ? 1 : 0;

        try {
            // Validate order_id exists
            $check_stmt = $pdo->prepare("SELECT order_id FROM orders WHERE order_id = ?");
            $check_stmt->execute([$order_id]);
            $order_exists = $check_stmt->fetch();

            if (!$order_exists) {
                throw new Exception("Order not found");
            }

            // Update order status
            $stmt = $pdo->prepare("UPDATE orders SET status = ? WHERE order_id = ?");
            $stmt->execute([$new_status, $order_id]);

            // Create order_status_log table if it doesn't exist
            $create_table_sql = "
                CREATE TABLE IF NOT EXISTS order_status_log (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    order_id INT NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    changed_by INT NOT NULL,
                    notes TEXT,
                    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (order_id) REFERENCES orders(order_id),
                    FOREIGN KEY (changed_by) REFERENCES admin_users(admin_id)
                )
            ";
            $pdo->exec($create_table_sql);

            // Create notifications table if it doesn't exist
            $create_notifications_table = "
                CREATE TABLE IF NOT EXISTS user_notifications (
                    notification_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    order_id INT NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    is_read TINYINT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    FOREIGN KEY (order_id) REFERENCES orders(order_id)
                )
            ";
            $pdo->exec($create_notifications_table);

            // Log the status change
            $stmt = $pdo->prepare("INSERT INTO order_status_log (order_id, status, changed_by, notes) VALUES (?, ?, ?, ?)");
            $notes = "Status changed to " . $new_status . ($notify_customer ? " - Customer notified" : "");
            $stmt->execute([$order_id, $new_status, $admin_id, $notes]);

            // Send notification to customer if enabled
            if ($notify_customer) {
                sendCustomerNotification($order_id, $new_status, $pdo);
            }

            // Redirect to avoid form resubmission
            header("Location: admindashboard.php?updated=" . $order_id . "&status=" . $new_status);
            exit();
        } catch (Exception $e) {
            error_log("Error updating order status: " . $e->getMessage());
            $update_error = "Failed to update order status. Error: " . $e->getMessage();
        }
    }
}

// Function to send customer notifications
function sendCustomerNotification($order_id, $new_status, $pdo)
{
    try {
        // Get order and customer details
        $stmt = $pdo->prepare("
            SELECT o.*, u.email, u.first_name, u.last_name, u.user_id 
            FROM orders o 
            JOIN users u ON o.user_id = u.user_id 
            WHERE o.order_id = ?
        ");
        $stmt->execute([$order_id]);
        $order = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$order)
            return false;

        $customer_user_id = $order['user_id'];
        $customer_email = $order['email'];
        $customer_name = $order['first_name'] . ' ' . $order['last_name'];

        // Prepare notification content based on status
        switch ($new_status) {
            case 'preparing':
                $title = "Order #" . $order_id . " is Being Prepared";
                $message = "Dear " . $customer_name . ",\n\n";
                $message .= "Your order #" . $order_id . " has been approved and is now being prepared.\n";
                $message .= "We'll notify you once it's ready for pickup.\n\n";
                $message .= "Thank you for choosing our canteen!";
                break;

            case 'ready':
                $title = "Order #" . $order_id . " is Ready for Pickup!";
                $message = "Dear " . $customer_name . ",\n\n";
                $message .= "Great news! Your order #" . $order_id . " is now ready for pickup.\n";
                $message .= "Please come to the canteen counter to collect your order.\n\n";
                $message .= "Thank you!";
                break;

            case 'completed':
                $title = "Order #" . $order_id . " Completed";
                $message = "Dear " . $customer_name . ",\n\n";
                $message .= "Your order #" . $order_id . " has been completed.\n";
                $message .= "Thank you for your purchase! We hope to serve you again soon.\n\n";
                $message .= "Best regards,\nUniversity Canteen";
                break;

            default:
                $title = "Order #" . $order_id . " Status Updated";
                $message = "Your order #" . $order_id . " status has been updated to: " . $new_status;
        }

        // Store notification in database for customer dashboard
        $notification_stmt = $pdo->prepare("
            INSERT INTO user_notifications (user_id, order_id, title, message) 
            VALUES (?, ?, ?, ?)
        ");
        $notification_stmt->execute([$customer_user_id, $order_id, $title, $message]);

        // For demo purposes, we'll also log the email
        $email_subject = "Order #" . $order_id . " Status Update";
        $notification_log = "[" . date('Y-m-d H:i:s') . "] Email to: " . $customer_email .
            " | Subject: " . $email_subject . " | Message: " . $message . "\n";
        file_put_contents('email_notifications.log', $notification_log, FILE_APPEND);

        return true;

    } catch (Exception $e) {
        error_log("Error sending customer notification: " . $e->getMessage());
        return false;
    }
}

// Fetch dashboard statistics
$stats = [];
try {
    // Total orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as total_orders FROM orders");
    $stmt->execute();
    $stats['total_orders'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_orders'];

    // Today's orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as today_orders FROM orders WHERE DATE(order_date) = CURDATE()");
    $stmt->execute();
    $stats['today_orders'] = $stmt->fetch(PDO::FETCH_ASSOC)['today_orders'];

    // Total revenue
    $stmt = $pdo->prepare("SELECT SUM(total) as total_revenue FROM orders WHERE status = 'completed'");
    $stmt->execute();
    $stats['total_revenue'] = $stmt->fetch(PDO::FETCH_ASSOC)['total_revenue'] ?? 0;

    // Today's revenue
    $stmt = $pdo->prepare("SELECT SUM(total) as today_revenue FROM orders WHERE status = 'completed' AND DATE(order_date) = CURDATE()");
    $stmt->execute();
    $stats['today_revenue'] = $stmt->fetch(PDO::FETCH_ASSOC)['today_revenue'] ?? 0;

    // Pending approval count
    $stmt = $pdo->prepare("SELECT COUNT(*) as pending_approval FROM orders WHERE status = 'pending'");
    $stmt->execute();
    $stats['pending_approval'] = $stmt->fetch(PDO::FETCH_ASSOC)['pending_approval'];

    // Preparing orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as preparing_orders FROM orders WHERE status = 'preparing'");
    $stmt->execute();
    $stats['preparing_orders'] = $stmt->fetch(PDO::FETCH_ASSOC)['preparing_orders'];

    // Ready orders count
    $stmt = $pdo->prepare("SELECT COUNT(*) as ready_orders FROM orders WHERE status = 'ready'");
    $stmt->execute();
    $stats['ready_orders'] = $stmt->fetch(PDO::FETCH_ASSOC)['ready_orders'];

    // Completed orders today
    $stmt = $pdo->prepare("SELECT COUNT(*) as completed_today FROM orders WHERE status = 'completed' AND DATE(order_date) = CURDATE()");
    $stmt->execute();
    $stats['completed_today'] = $stmt->fetch(PDO::FETCH_ASSOC)['completed_today'];

    // Average order value
    $stmt = $pdo->prepare("SELECT AVG(total) as avg_order_value FROM orders WHERE status = 'completed'");
    $stmt->execute();
    $stats['avg_order_value'] = $stmt->fetch(PDO::FETCH_ASSOC)['avg_order_value'] ?? 0;

} catch (Exception $e) {
    error_log("Error fetching dashboard statistics: " . $e->getMessage());
    $stats = [
        'total_orders' => 0,
        'today_orders' => 0,
        'total_revenue' => 0,
        'today_revenue' => 0,
        'pending_approval' => 0,
        'preparing_orders' => 0,
        'ready_orders' => 0,
        'completed_today' => 0,
        'avg_order_value' => 0
    ];
}

// Fetch orders by status
$pending_orders = [];
$preparing_orders = [];
$ready_orders = [];

try {
    // Check if required tables exist
    $tables_check = $pdo->query("SHOW TABLES LIKE 'orders'")->fetch();
    if (!$tables_check) {
        throw new Exception("Orders table does not exist");
    }

    // Fetch pending orders
    $stmt = $pdo->prepare("
        SELECT o.*, u.first_name, u.last_name, u.email, u.user_id
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.user_id 
        WHERE o.status = 'pending'
        ORDER BY o.order_date ASC
    ");
    $stmt->execute();
    $pending_orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch preparing orders
    $stmt = $pdo->prepare("
        SELECT o.*, u.first_name, u.last_name, u.email, u.user_id
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.user_id 
        WHERE o.status = 'preparing'
        ORDER BY o.order_date ASC
    ");
    $stmt->execute();
    $preparing_orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Fetch ready orders
    $stmt = $pdo->prepare("
        SELECT o.*, u.first_name, u.last_name, u.email, u.user_id
        FROM orders o 
        LEFT JOIN users u ON o.user_id = u.user_id 
        WHERE o.status = 'ready'
        ORDER BY o.order_date ASC
    ");
    $stmt->execute();
    $ready_orders = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Get order items for all orders
    $all_orders = array_merge($pending_orders, $preparing_orders, $ready_orders);

    foreach ($all_orders as &$order) {
        // Get item count
        $stmt = $pdo->prepare("SELECT COUNT(*) as item_count FROM order_items WHERE order_id = ?");
        $stmt->execute([$order['order_id']]);
        $item_count = $stmt->fetch(PDO::FETCH_ASSOC);
        $order['item_count'] = $item_count['item_count'] ?? 0;

        // Get item names
        $stmt = $pdo->prepare("
            SELECT mi.name, oi.quantity 
            FROM order_items oi 
            JOIN menu_items mi ON oi.item_id = mi.item_id 
            WHERE oi.order_id = ?
        ");
        $stmt->execute([$order['order_id']]);
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $item_names = [];
        foreach ($items as $item) {
            $item_names[] = $item['quantity'] . 'x ' . $item['name'];
        }
        $order['item_names'] = implode(', ', $item_names);

        // Fix the items display - use item_names instead of items
        $order['items'] = $order['item_names'];
    }
    unset($order);

} catch (Exception $e) {
    error_log("Error fetching orders: " . $e->getMessage());
}

// Process logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header('Location: adminsignin.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - University Canteen Kiosk</title>
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
        }

        .container {
            display: flex;
            min-height: 100vh;
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
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 20px;
        }

        .logo {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
            margin-right: 10px;
        }

        .logo-text {
            font-size: 1.2rem;
            font-weight: 700;
        }

        .logo-text .canteen {
            color: var(--primary);
        }

        .logo-text .kiosk {
            color: white;
        }

        .admin-info {
            display: flex;
            align-items: center;
        }

        .admin-avatar {
            width: 40px;
            height: 40px;
            background: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            margin-right: 10px;
        }

        .admin-details {
            flex: 1;
        }

        .admin-name {
            font-weight: 600;
            font-size: 0.9rem;
        }

        .admin-role {
            font-size: 0.8rem;
            color: var(--secondary);
        }

        .sidebar-menu {
            flex: 1;
        }

        .menu-item {
            display: flex;
            align-items: center;
            padding: 12px 20px;
            color: rgba(255, 255, 255, 0.7);
            text-decoration: none;
            transition: var(--transition);
        }

        .menu-item:hover, .menu-item.active {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }

        .menu-item i {
            margin-right: 10px;
            width: 20px;
            text-align: center;
        }

        .sidebar-footer {
            padding: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .logout-btn {
            display: flex;
            align-items: center;
            color: rgba(255, 255, 255, 0.7);
            text-decoration: none;
            transition: var(--transition);
        }

        .logout-btn:hover {
            color: white;
        }

        .logout-btn i {
            margin-right: 10px;
        }

        /* Main Content Styles */
        .main-content {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .page-title {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .welcome-text {
            color: var(--secondary);
            margin-top: 5px;
        }

        /* Dashboard Stats */
        .dashboard-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
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
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 16px;
            font-size: 24px;
            color: white;
        }

        .orders-icon {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
        }

        .preparing-icon {
            background: linear-gradient(135deg, var(--info) 0%, #3aafd9 100%);
        }

        .revenue-icon {
            background: linear-gradient(135deg, var(--success) 0%, #3acf5d 100%);
        }

        .pending-icon {
            background: linear-gradient(135deg, var(--warning) 0%, #ffd351 100%);
        }

        .stat-value {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 4px;
            color: var(--dark);
        }

        .stat-label {
            font-size: 14px;
            color: var(--secondary);
        }

        /* Order Sections */
        .order-section {
            background: white;
            border-radius: var(--radius);
            margin-bottom: 30px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .section-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--light);
        }

        .section-title {
            display: flex;
            align-items: center;
            font-size: 18px;
            font-weight: 600;
            color: var(--dark);
        }

        .section-title i {
            margin-right: 10px;
            color: var(--primary);
        }

        .order-count {
            background: var(--primary);
            color: white;
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 12px;
            margin-left: 10px;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            text-decoration: none;
            transition: var(--transition);
            border: none;
            cursor: pointer;
        }

        .btn-view {
            background: var(--light-gray);
            color: var(--dark);
        }

        .btn-view:hover {
            background: #dde1e7;
        }

        .btn i {
            margin-right: 6px;
        }

        /* Orders Grid */
        .orders-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 20px;
            padding: 24px;
        }

        .order-card {
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            transition: var(--transition);
            background: white;
        }

        .order-card:hover {
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            border-color: var(--primary);
        }

        .order-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }

        .order-id {
            font-weight: 600;
            font-size: 16px;
            color: var(--dark);
            margin-bottom: 4px;
        }

        .customer-info {
            font-size: 13px;
            color: var(--secondary);
        }

        .order-time {
            font-size: 12px;
            color: var(--secondary);
            text-align: right;
        }

        .order-details {
            margin-bottom: 16px;
        }

        .order-items {
            font-size: 14px;
            margin-bottom: 12px;
            line-height: 1.5;
            color: var(--dark);
        }

        .order-meta {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .meta-label {
            color: var(--secondary);
        }

        .meta-value {
            font-weight: 600;
            color: var(--dark);
        }

        .action-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
        }

        .btn-approve {
            background: var(--success);
            color: white;
            flex: 1;
            justify-content: center;
        }

        .btn-approve:hover {
            background: #218838;
        }

        .btn-ready {
            background: var(--info);
            color: white;
            flex: 1;
            justify-content: center;
        }

        .btn-ready:hover {
            background: #138496;
        }

        .btn-complete {
            background: var(--primary);
            color: white;
            flex: 1;
            justify-content: center;
        }

        .btn-complete:hover {
            background: var(--primary-dark);
        }

        .notification-toggle {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 13px;
            color: var(--secondary);
        }

        .toggle-label {
            font-size: 13px;
        }

        .switch {
            position: relative;
            display: inline-block;
            width: 46px;
            height: 24px;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 24px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background-color: var(--success);
        }

        input:checked + .slider:before {
            transform: translateX(22px);
        }

        /* Alert Styles */
        .alert {
            padding: 12px 16px;
            border-radius: var(--radius);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .alert-success {
            background: rgba(76, 201, 240, 0.1);
            color: #0a58ca;
            border-left: 4px solid var(--success);
        }

        .alert-danger {
            background: rgba(247, 37, 133, 0.1);
            color: var(--danger);
            border-left: 4px solid var(--danger);
        }

        .alert i {
            font-size: 20px;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--secondary);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 15px;
            color: var(--light-gray);
        }

        .empty-state h3 {
            margin-bottom: 10px;
            color: var(--dark);
        }

        /* Responsive Styles */
        @media (max-width: 768px) {
            .container {
                flex-direction: column;
            }
            
            .sidebar {
                width: 100%;
                padding: 10px;
            }
            
            .dashboard-stats {
                grid-template-columns: 1fr;
            }
            
            .orders-grid {
                grid-template-columns: 1fr;
                padding: 16px;
            }
            
            .page-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .section-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }
            
            .action-buttons {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <div class="logo-icon">
                        <i class="fas fa-utensils"></i>
                    </div>
                    <div class="logo-text">
                        <span class="canteen">Canteen</span><span class="kiosk">Kiosk</span>
                    </div>
                </div>
                
                <div class="admin-info">
                    <div class="admin-avatar">
                        <?php echo strtoupper(substr($admin_full_name, 0, 1)); ?>
                    </div>
                    <div class="admin-details">
                        <div class="admin-name"><?php echo htmlspecialchars($admin_full_name); ?></div>
                        <div class="admin-role"><?php echo htmlspecialchars(ucfirst($admin_role)); ?></div>
                    </div>
                </div>
            </div>
            
            <div class="sidebar-menu">
                <a href="admindashboard.php" class="menu-item active">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </a>
                <a href="admin_orders.php" class="menu-item">
                    <i class="fas fa-shopping-cart"></i>
                    <span>Orders</span>
                </a>
                <a href="admin_menu.php" class="menu-item">
                    <i class="fas fa-utensils"></i>
                    <span>Menu</span>
                </a>
                <a href="admin_users.php" class="menu-item">
                    <i class="fas fa-users"></i>
                    <span>Users</span>
                </a>
                <a href="admin_reports.php" class="menu-item">
                    <i class="fas fa-chart-bar"></i>
                    <span>Reports</span>
                </a>
                <a href="admin_settings.php" class="menu-item">
                    <i class="fas fa-cog"></i>
                    <span>Settings</span>
                </a>
            </div>
            
            <div class="sidebar-footer">
                <a href="?action=logout" class="logout-btn">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Logout</span>
                </a>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <div class="page-header">
                <div>
                    <h1 class="page-title">Admin Dashboard</h1>
                    <p class="welcome-text">Welcome back, <?php echo htmlspecialchars($admin_full_name); ?>! Monitor and manage canteen operations.</p>
                </div>
                <div style="color: var(--secondary); font-size: 0.9rem;">
                    <i class="fas fa-calendar-alt"></i> <?php echo date('F j, Y'); ?>
                </div>
            </div>

            <?php if (isset($_GET['updated'])): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                Order #<?php echo htmlspecialchars($_GET['updated']); ?> has been updated to <?php echo htmlspecialchars($_GET['status']); ?> successfully.
            </div>
            <?php endif; ?>

            <?php if (isset($update_error)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                <span><?php echo $update_error; ?></span>
            </div>
            <?php endif; ?>
            
            <!-- Statistics Cards -->
            <div class="dashboard-stats">
                <div class="stat-card">
                    <div class="stat-icon orders-icon">
                        <i class="fas fa-shopping-cart"></i>
                    </div>
                    <div class="stat-info">
                        <div class="stat-value"><?php echo $stats['today_orders'] ?? 0; ?></div>
                        <div class="stat-label">Today's Orders</div>
                    </div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon preparing-icon">
                        <i class="fas fa-utensils"></i>
                    </div>
                    <div class="stat-info">
                        <div class="stat-value"><?php echo $stats['preparing_orders'] ?? 0; ?></div>
                        <div class="stat-label">Being Prepared</div>
                    </div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon revenue-icon">
                        <i class="fas fa-dollar-sign"></i>
                    </div>
                    <div class="stat-info">
                        <div class="stat-value">RM<?php echo number_format($stats['today_revenue'] ?? 0, 2); ?></div>
                        <div class="stat-label">Today's Revenue</div>
                    </div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon pending-icon">
                        <i class="fas fa-hourglass-half"></i>
                    </div>
                    <div class="stat-info">
                        <div class="stat-value"><?php echo $stats['pending_approval'] ?? 0; ?></div>
                        <div class="stat-label">Pending Approval</div>
                    </div>
                </div>
            </div>
            
            <!-- Pending Orders Section -->
            <div class="order-section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-clock"></i>
                        <span>Pending Orders</span>
                        <span class="order-count"><?php echo count($pending_orders); ?></span>
                    </div>
                    <a href="admin_orders.php?filter=pending" class="btn btn-view">
                        <i class="fas fa-list"></i>
                        <span>View All</span>
                    </a>
                </div>
                
                <div class="orders-grid">
                    <?php if (count($pending_orders) > 0): ?>
                        <?php foreach ($pending_orders as $order): ?>
                        <div class="order-card">
                            <div class="order-header">
                                <div>
                                    <div class="order-id">Order #<?php echo htmlspecialchars($order['order_id']); ?></div>
                                    <div class="customer-info">
                                        <?php echo htmlspecialchars($order['first_name'] . ' ' . $order['last_name']); ?>
                                    </div>
                                </div>
                                <div class="order-time">
                                    <?php echo date('h:i A', strtotime($order['order_date'])); ?>
                                </div>
                            </div>
                            
                            <div class="order-details">
                                <div class="order-items">
                                    <strong>Items:</strong> <?php echo htmlspecialchars($order['items']); ?>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Total:</span>
                                    <span class="meta-value">RM<?php echo number_format($order['total'], 2); ?></span>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Items:</span>
                                    <span class="meta-value"><?php echo $order['total']; ?></span>
                                </div>
                            </div>
                            
                            <form method="POST" class="order-form">
                                <input type="hidden" name="order_id" value="<?php echo $order['order_id']; ?>">
                                <input type="hidden" name="status" value="preparing">
                                
                                <div class="action-buttons">
                                    <button type="submit" name="update_order_status" class="btn btn-approve">
                                        <i class="fas fa-check"></i>
                                        <span>Approve Order</span>
                                    </button>
                                </div>
                                
                                <div class="notification-toggle">
                                    <span class="toggle-label">Notify Customer</span>
                                    <label class="switch">
                                        <input type="checkbox" name="notify_customer" checked>
                                        <span class="slider"></span>
                                    </label>
                                </div>
                            </form>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state" style="grid-column: 1 / -1;">
                            <i class="fas fa-clock"></i>
                            <h3>No Pending Orders</h3>
                            <p>All orders have been processed. New orders will appear here when customers place them.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Orders Being Prepared Section -->
            <div class="order-section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-utensils"></i>
                        <span>Orders Being Prepared</span>
                        <span class="order-count"><?php echo count($preparing_orders); ?></span>
                    </div>
                    <a href="admin_orders.php?filter=preparing" class="btn btn-view">
                        <i class="fas fa-list"></i>
                        <span>View All</span>
                    </a>
                </div>
                
                <div class="orders-grid">
                    <?php if (count($preparing_orders) > 0): ?>
                        <?php foreach ($preparing_orders as $order): ?>
                        <div class="order-card">
                            <div class="order-header">
                                <div>
                                    <div class="order-id">Order #<?php echo htmlspecialchars($order['order_id']); ?></div>
                                    <div class="customer-info">
                                        <?php echo htmlspecialchars($order['first_name'] . ' ' . $order['last_name']); ?>
                                    </div>
                                </div>
                                <div class="order-time">
                                    <?php echo date('h:i A', strtotime($order['order_date'])); ?>
                                </div>
                            </div>
                            
                            <div class="order-details">
                                <div class="order-items">
                                    <strong>Items:</strong> <?php echo htmlspecialchars($order['items']); ?>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Total:</span>
                                    <span class="meta-value">RM<?php echo number_format($order['total'], 2); ?></span>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Items:</span>
                                    <span class="meta-value"><?php echo $order['total']; ?></span>
                                </div>
                            </div>
                            
                            <form method="POST" class="order-form">
                                <input type="hidden" name="order_id" value="<?php echo $order['order_id']; ?>">
                                <input type="hidden" name="status" value="ready">
                                
                                <div class="action-buttons">
                                    <button type="submit" name="update_order_status" class="btn btn-ready">
                                        <i class="fas fa-check-circle"></i>
                                        <span>Mark as Ready</span>
                                    </button>
                                </div>
                                
                                <div class="notification-toggle">
                                    <span class="toggle-label">Notify Customer</span>
                                    <label class="switch">
                                        <input type="checkbox" name="notify_customer" checked>
                                        <span class="slider"></span>
                                    </label>
                                </div>
                            </form>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state" style="grid-column: 1 / -1;">
                            <i class="fas fa-utensils"></i>
                            <h3>No Orders Being Prepared</h3>
                            <p>All orders are either pending approval or ready for pickup.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Ready for Pickup Section -->
            <div class="order-section">
                <div class="section-header">
                    <div class="section-title">
                        <i class="fas fa-box"></i>
                        <span>Ready for Pickup</span>
                        <span class="order-count"><?php echo count($ready_orders); ?></span>
                    </div>
                    <a href="admin_orders.php?filter=ready" class="btn btn-view">
                        <i class="fas fa-list"></i>
                        <span>View All</span>
                    </a>
                </div>
                
                <div class="orders-grid">
                    <?php if (count($ready_orders) > 0): ?>
                        <?php foreach ($ready_orders as $order): ?>
                        <div class="order-card">
                            <div class="order-header">
                                <div>
                                    <div class="order-id">Order #<?php echo htmlspecialchars($order['order_id']); ?></div>
                                    <div class="customer-info">
                                        <?php echo htmlspecialchars($order['first_name'] . ' ' . $order['last_name']); ?>
                                    </div>
                                </div>
                                <div class="order-time">
                                    <?php echo date('h:i A', strtotime($order['order_date'])); ?>
                                </div>
                            </div>
                            
                            <div class="order-details">
                                <div class="order-items">
                                    <strong>Items:</strong> <?php echo htmlspecialchars($order['items']); ?>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Total:</span>
                                    <span class="meta-value">RM<?php echo number_format($order['total'], 2); ?></span>
                                </div>
                                
                                <div class="order-meta">
                                    <span class="meta-label">Items:</span>
                                    <span class="meta-value"><?php echo $order['total']; ?></span>
                                </div>
                            </div>
                            
                            <form method="POST" class="order-form">
                                <input type="hidden" name="order_id" value="<?php echo $order['order_id']; ?>">
                                <input type="hidden" name="status" value="completed">
                                
                                <div class="action-buttons">
                                    <button type="submit" name="update_order_status" class="btn btn-complete">
                                        <i class="fas fa-check-double"></i>
                                        <span>Mark as Completed</span>
                                    </button>
                                </div>
                                
                                <div class="notification-toggle">
                                    <span class="toggle-label">Notify Customer</span>
                                    <label class="switch">
                                        <input type="checkbox" name="notify_customer" checked>
                                        <span class="slider"></span>
                                    </label>
                                </div>
                            </form>
                        </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state" style="grid-column: 1 / -1;">
                            <i class="fas fa-box"></i>
                            <h3>No Orders Ready for Pickup</h3>
                            <p>Orders will appear here once they are prepared and ready for customer pickup.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Auto-hide success alerts after 5 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                if (alert.classList.contains('alert-success')) {
                    alert.style.transition = 'opacity 0.5s ease';
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 500);
                }
            });
        }, 5000);

        // Form submission confirmation
        document.querySelectorAll('.order-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const button = this.querySelector('button[type="submit"]');
                const orderId = this.querySelector('input[name="order_id"]').value;
                const newStatus = this.querySelector('input[name="status"]').value;
                
                let message = '';
                switch(newStatus) {
                    case 'preparing':
                        message = `Are you sure you want to approve Order #${orderId} and mark it as "Being Prepared"?`;
                        break;
                    case 'ready':
                        message = `Are you sure you want to mark Order #${orderId} as "Ready for Pickup"?`;
                        break;
                    case 'completed':
                        message = `Are you sure you want to mark Order #${orderId} as "Completed"?`;
                        break;
                }
                
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>