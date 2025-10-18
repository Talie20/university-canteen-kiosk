<?php
// Include the database connection
include 'db.php';
session_start();

// Initialize variables
$error = '';
$max_attempts = 2;

// Handle clear recent logins request
if (isset($_GET['clear_recent']) && $_GET['clear_recent'] === 'true') {
    setcookie('recent_logins', '', time() - 3600, '/');
    header('Location: signin.php');
    exit();
}

// Handle forgot password request
if (isset($_POST['forgot_password'])) {
    $email = trim($_POST['email']);

    if (empty($email)) {
        $error = 'Please enter your email address.';
    } else {
        try {
            // Check if email exists in users table
            $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            // If not found in users table, check admin_users table
            if (!$user) {
                $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE email = ?");
                $stmt->execute([$email]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $is_admin = true;
            } else {
                $is_admin = false;
            }

            if ($user) {
                // Generate password reset token
                $reset_token = bin2hex(random_bytes(32));
                $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

                // Store token in appropriate database table
                if ($is_admin) {
                    $stmt = $pdo->prepare("UPDATE admin_users SET reset_token = ?, reset_expiry = ? WHERE email = ?");
                } else {
                    $stmt = $pdo->prepare("UPDATE users SET reset_token = ?, reset_expiry = ? WHERE email = ?");
                }
                $stmt->execute([$reset_token, $expiry, $email]);

                // Reset login attempts for this user (using correct table name from screenshot)
                $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE user_id = ?");
                $stmt->execute([$user['user_id']]);

                // Send reset email (pseudo-code)
                $reset_link = "http://" . $_SERVER['HTTP_HOST'] . "/reset_password.php?token=" . $reset_token;
                $subject = "Password Reset Request";
                $message = "Hello " . $user['first_name'] . ",\n\n";
                $message .= "You requested a password reset. Click the link below to reset your password:\n";
                $message .= $reset_link . "\n\n";
                $message .= "This link will expire in 1 hour.\n\n";
                $message .= "If you didn't request this, please ignore this email.\n";

                // In a real implementation, use a library like PHPMailer
                // mail($email, $subject, $message);

                $success_message = "Password reset instructions have been sent to your email.";
            } else {
                $error = 'No account found with that email address.';
            }
        } catch (PDOException $e) {
            $error = 'Database error: ' . $e->getMessage();
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user_id'])) {
    // Get form data
    $user_id = trim($_POST['user_id']);
    $password = trim($_POST['password']);

    // Validate inputs
    if (empty($user_id) || empty($password)) {
        $error = 'Both fields are required.';
    } else {
        try {
            // Check if user is locked out (using correct table name from screenshot)
            $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE user_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
            $stmt->execute([$user_id]);
            $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
            $login_attempts = (int) $attempts_data['attempts'];

            if ($login_attempts >= $max_attempts) {
                $error = 'Too many failed attempts for this account. Please use the forgot password option to reset your password.';
            } else {
                // Check if user exists in users table
                $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
                $stmt->execute([$user_id]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $is_admin = false;

                // If not found in users table, check admin_users table
                if (!$user) {
                    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE user_id = ?");
                    $stmt->execute([$user_id]);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    $is_admin = true;
                }

                if ($user) {
                    // Verify password
                    if (password_verify($password, $user['password'])) {
                        // Clear login attempts on successful login (using correct table name)
                        $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE user_id = ?");
                        $stmt->execute([$user_id]);

                        // Set session variables
                        $_SESSION['user_id'] = $user['user_id'];
                        $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
                        $_SESSION['is_admin'] = $is_admin;

                        // Add to recent logins (only for regular users, not admins)
                        if (!$is_admin) {
                            $recentLogins = isset($_COOKIE['recent_logins']) ? json_decode($_COOKIE['recent_logins'], true) : [];

                            // Remove if already exists
                            $recentLogins = array_filter($recentLogins, function ($login) use ($user_id) {
                                return $login['user_id'] !== $user_id;
                            });

                            // Add to beginning
                            array_unshift($recentLogins, [
                                'user_id' => $user['user_id'],
                                'name' => $user['first_name'] . ' ' . $user['last_name'],
                                'email' => $user['email'],
                                'timestamp' => time()
                            ]);

                            // Keep only last 5
                            $recentLogins = array_slice($recentLogins, 0, 5);

                            // Store in cookie
                            setcookie('recent_logins', json_encode($recentLogins), time() + (30 * 24 * 60 * 60), '/');
                        }

                        // Redirect to appropriate dashboard
                        if ($is_admin) {
                            header('Location: admin_dashboard.php');
                        } else {
                            header('Location: dashboard.php');
                        }
                        exit();
                    } else {
                        // Record failed login attempt for both regular users and admins (using correct table name)
                        $stmt = $pdo->prepare("INSERT INTO login_attempts (user_id, attempt_time) VALUES (?, NOW())");
                        $stmt->execute([$user_id]);

                        // Get updated attempt count
                        $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE user_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
                        $stmt->execute([$user_id]);
                        $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
                        $login_attempts = (int) $attempts_data['attempts'];

                        if ($login_attempts >= $max_attempts) {
                            $error = 'Too many failed attempts for this account. Please use the forgot password option to reset your password.';
                        } else {
                            $remaining_attempts = $max_attempts - $login_attempts;
                            $error = 'Invalid User ID or Password. ' . $remaining_attempts . ' attempt(s) remaining for this account.';
                        }
                    }
                } else {
                    // For non-existent users, we don't record attempts to prevent user enumeration attacks
                    $error = 'Invalid User ID or Password.';
                }
            }
        } catch (PDOException $e) {
            $error = 'Database error: ' . $e->getMessage();
        }
    }
}

// Get recent logins from cookie (only regular users)
$recentLogins = isset($_COOKIE['recent_logins']) ? json_decode($_COOKIE['recent_logins'], true) : [];

// Get all users for autofill suggestions (only regular users, not admins)
$allUsers = [];
try {
    $stmt = $pdo->prepare("SELECT user_id, first_name, last_name FROM users ORDER BY created_at DESC LIMIT 10");
    $stmt->execute();
    $allUsers = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Silently fail - we'll just have an empty suggestions list
}

// Check if the current user input corresponds to a locked account
$is_locked = false;
if (isset($_POST['user_id'])) {
    $user_id_input = trim($_POST['user_id']);
    if (!empty($user_id_input)) {
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE user_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
            $stmt->execute([$user_id_input]);
            $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
            $is_locked = ((int) $attempts_data['attempts'] >= $max_attempts);
        } catch (PDOException $e) {
            // Silently fail
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In - University CanteenKiosk</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* ALL CSS REMAINS EXACTLY THE SAME - NO CHANGES */
        :root {
            --primary: #f88964;
            --secondary: #020c02ff;
            --dark: #333;
            --light: #f9f9f9;
            --gray: #777;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --error: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }
        
        body {
            background-color: #f5f5f5;
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            width: 100%;
            max-width: 450px;
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
            user-select: none;
        }
        
        .logo span {
            color: var(--secondary);
        }
        
        .logo p {
            color: var(--gray);
            margin-top: 10px;
            user-select: none;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: var(--shadow);
            margin-bottom: 20px;
            position: relative;
        }
        
        .card-header {
            text-align: center;
            margin-bottom: 25px;
            position: relative;
        }
        
        .card-header h2 {
            font-size: 1.8rem;
            color: var(--dark);
            margin-bottom: 10px;
            user-select: none;
        }
        
        .card-header p {
            color: var(--gray);
            user-select: none;
        }
        
        .card-header::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
            width: 50px;
            height: 3px;
            background: var(--primary);
            border-radius: 3px;
        }
        
        .form-group {
            margin-bottom: 20px;
            position: relative;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark);
            user-select: none;
        }
        
        .input-with-icon {
            position: relative;
        }
        
        .input-with-icon i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--gray);
            z-index: 2;
            pointer-events: none;
        }
        
        .input-with-icon input {
            width: 100%;
            padding: 12px 15px 12px 45px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background-color: #fff !important;
            position: relative;
            z-index: 1;
        }
        
        .input-with-icon input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(248, 137, 100, 0.2);
            outline: none;
        }
        
        .autofill-suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 8px 8px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: none;
        }
        
        .autofill-suggestion {
            padding: 10px 15px;
            cursor: pointer;
            transition: background-color 0.2s;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .autofill-suggestion:hover {
            background-color: #f5f5f5;
        }
        
        .autofill-suggestion:not(:last-child) {
            border-bottom: 1px solid #eee;
        }
        
        .user-id {
            font-weight: 500;
            color: var(--primary);
            flex: 1;
            text-align: right;
        }
        
        .user-name {
            color: var(--gray);
            font-size: 0.9rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin-right: 10px;
            flex: 1;
        }
        
        .error {
            color: var(--error);
            font-size: 0.9rem;
            margin-top: 5px;
            display: block;
            text-align: center;
            padding: 10px;
            background: rgba(231, 76, 60, 0.1);
            border-radius: 5px;
            margin-bottom: 15px;
            user-select: none;
        }
        
        .success {
            color: var(--success);
            font-size: 0.9rem;
            margin-top: 5px;
            display: block;
            text-align: center;
            padding: 10px;
            background: rgba(39, 174, 96, 0.1);
            border-radius: 5px;
            margin-bottom: 15px;
            user-select: none;
        }
        
        button {
            width: 100%;
            padding: 12px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
            position: relative;
            overflow: hidden;
            user-select: none;
        }
        
        button:hover {
            background: #e67a57;
        }
        
        button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .signup-link {
            text-align: center;
            margin-top: 20px;
            color: var(--gray);
            user-select: none;
        }
        
        .signup-link a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            display: block;
            margin-top: 10px;
            padding: 10px;
            border: 1px solid var(--primary);
            border-radius: 8px;
        }
        
        .signup-link a:hover {
            background: var(--primary);
            color: white;
            text-decoration: none;
        }
        
        .forgot-password {
            text-align: center;
            margin-top: 15px;
        }
        
        .forgot-password a {
            color: var(--primary);
            text-decoration: none;
            font-size: 0.9rem;
        }
        
        .forgot-password a:hover {
            text-decoration: underline;
        }
        
        .recent-accounts {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: var(--shadow);
        }
        
        .recent-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            user-select: none;
        }
        
        .recent-accounts h3 {
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 0;
        }
        
        .reset-recent {
            background: none;
            border: none;
            color: #e74c3c;
            cursor: pointer;
            font-size: 0.8rem;
            display: flex;
            align-items: center;
            gap: 5px;
            padding: 5px 10px;
            border-radius: 5px;
            transition: all 0.3s ease;
            text-decoration: none;
        }
        
        .reset-recent:hover {
            background: rgba(231, 76, 60, 0.1);
        }
        
        .recent-account {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
            transition: all 0.3s ease;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        
        .recent-account:hover {
            background-color: #f9f9f9;
            transform: translateY(-2px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .account-info {
            flex: 1;
        }
        
        .account-name {
            font-weight: 500;
            color: var(--dark);
            margin-bottom: 4px;
        }
        
        .account-id {
            font-size: 0.9rem;
            color: var(--primary);
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .account-email {
            font-size: 0.85rem;
            color: #888;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 200px;
        }
        
        .account-time {
            font-size: 0.8rem;
            color: var(--gray);
            text-align: right;
            min-width: 60px;
        }
        
        .autofill-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--primary);
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: var(--shadow);
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 10px;
            transform: translateX(100%);
            opacity: 0;
            transition: all 0.3s ease;
        }
        
        .autofill-notification.show {
            transform: translateX(0);
            opacity: 1;
        }
        
        .no-recent {
            text-align: center;
            color: var(--gray);
            padding: 20px;
            font-style: italic;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: white;
            margin: 10% auto;
            padding: 20px;
            border-radius: 15px;
            width: 90%;
            max-width: 400px;
            box-shadow: var(--shadow);
            position: relative;
        }
        
        .close-modal {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close-modal:hover {
            color: black;
        }
        
        .modal-header {
            margin-bottom: 20px;
            text-align: center;
        }
        
        .modal-header h3 {
            color: var(--primary);
        }
        
        .account-locked {
            background-color: rgba(231, 76, 60, 0.1);
            border: 1px solid rgba(231, 76, 60, 0.3);
        }
        
        .account-locked-message {
            color: var(--error);
            font-size: 0.9rem;
            margin-top: 5px;
            display: block;
            text-align: center;
            padding: 10px;
            background: rgba(231, 76, 60, 0.1);
            border-radius: 5px;
            margin-bottom: 15px;
            user-select: none;
        }
        
        @media (max-width: 480px) {
            .card {
                padding: 20px;
            }
            
            .logo h1 {
                font-size: 2rem;
            }
            
            .account-email {
                max-width: 150px;
            }
            
            .autofill-notification {
                top: 10px;
                right: 10px;
                left: 10px;
                transform: translateY(-100%);
            }
            
            .autofill-notification.show {
                transform: translateY(0);
            }
            
            .recent-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .reset-recent {
                align-self: flex-end;
            }
            
            .modal-content {
                margin: 20% auto;
                width: 95%;
            }
        }
    </style>
</head>
<body>
    <div class="autofill-notification" id="autofillNotification">
        <i class="fas fa-check-circle"></i>
        <span id="notificationText"></span>
    </div>

    <!-- Forgot Password Modal -->
    <div id="forgotPasswordModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-key"></i> Reset Password</h3>
            </div>
            <?php if (isset($success_message)): ?>
                <div class="success"><?php echo htmlspecialchars($success_message); ?></div>
            <?php endif; ?>
            <form method="post" id="forgotPasswordForm">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="email" name="email" required placeholder="Enter your email address">
                    </div>
                </div>
                <button type="submit" name="forgot_password"><i class="fas fa-paper-plane"></i> Send Reset Link</button>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="logo">
            <h1>Canteen<span>Kiosk</span></h1>
            <p>University Food Ordering System</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>Sign In</h2>
                <p>Access your account to order delicious food</p>
            </div>
            
            <?php if (!empty($error)): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($is_locked): ?>
                <div class="account-locked-message">
                    <i class="fas fa-lock"></i> This account has been locked due to too many failed attempts.
                </div>
            <?php endif; ?>
            
            <form method="post" id="signinForm" autocomplete="off">
                <div class="form-group">
                    <label for="user_id">User ID</label>
                    <div class="input-with-icon">
                        <i class="fas fa-id-card"></i>
                        <input type="text" id="user_id" name="user_id" required placeholder="Enter your User ID (e.g., INST-338445)" autocomplete="off" data-lpignore="true" data-form-type="other" value="<?php echo isset($_POST['user_id']) ? htmlspecialchars($_POST['user_id']) : ''; ?>">
                        <div class="autofill-suggestions" id="userSuggestions">
                            <?php foreach ($allUsers as $user): ?>
                                <div class="autofill-suggestion" data-user-id="<?php echo htmlspecialchars($user['user_id']); ?>">
                                    <span class="user-name"><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></span>
                                    <span class="user-id"><?php echo htmlspecialchars($user['user_id']); ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" name="password" required placeholder="Enter your password" autocomplete="new-password" data-lpignore="true">
                    </div>
                </div>
                
                <button type="submit" id="submitButton">
                    <i class="fas fa-sign-in-alt"></i> Sign In
                </button>
                
                <div class="forgot-password">
                    <a href="#" id="forgotPasswordLink">Forgot Password?</a>
                </div>
            </form>
            
            <div class="signup-link">
                <p>Don't have an account?</p>
                <a href="signup.php" id="signupLink"><i class="fas fa-user-plus"></i> Sign Up</a>
            </div>
        </div>

        <?php if (!empty($recentLogins)): ?>
        <div class="recent-accounts" id="recentAccountsContainer">
            <div class="recent-header">
                <h3><i class="fas fa-history"></i> Recent Accounts</h3>
                <a href="signin.php?clear_recent=true" class="reset-recent" id="resetRecent">
                    <i class="fas fa-trash-alt"></i> Clear History
                </a>
            </div>
            <div id="recentAccountsList">
                <?php foreach ($recentLogins as $login):
                    $timeAgo = '';
                    $timeDiff = time() - $login['timestamp'];
                    if ($timeDiff < 60) {
                        $timeAgo = 'Just now';
                    } elseif ($timeDiff < 3600) {
                        $minutes = floor($timeDiff / 60);
                        $timeAgo = $minutes . 'm ago';
                    } elseif ($timeDiff < 86400) {
                        $hours = floor($timeDiff / 3600);
                        $timeAgo = $hours . 'h ago';
                    } else {
                        $days = floor($timeDiff / 86400);
                        $timeAgo = $days . 'd ago';
                    }

                    // Check if this recent account is locked
                    $is_recent_locked = false;
                    try {
                        $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM login_attempts WHERE user_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
                        $stmt->execute([$login['user_id']]);
                        $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
                        $is_recent_locked = ((int) $attempts_data['attempts'] >= $max_attempts);
                    } catch (PDOException $e) {
                        // Silently fail
                    }
                    ?>
                    <div class="recent-account <?php echo $is_recent_locked ? 'account-locked' : ''; ?>" data-user-id="<?php echo htmlspecialchars($login['user_id']); ?>">
                        <div class="account-info">
                            <div class="account-name"><?php echo htmlspecialchars($login['name']); ?></div>
                            <div class="account-id">ID: <?php echo htmlspecialchars($login['user_id']); ?></div>
                            <div class="account-email" title="<?php echo htmlspecialchars($login['email']); ?>">
                                <?php echo htmlspecialchars($login['email']); ?>
                            </div>
                            <?php if ($is_recent_locked): ?>
                                <div class="account-locked-message">
                                    <i class="fas fa-lock"></i> Account locked
                                </div>
                            <?php endif; ?>
                        </div>
                        <div class="account-time">
                            <?php echo $timeAgo; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const userIdInput = document.getElementById('user_id');
            const passwordInput = document.getElementById('password');
            const userSuggestions = document.getElementById('userSuggestions');
            const recentAccounts = document.querySelectorAll('.recent-account');
            const autofillNotification = document.getElementById('autofillNotification');
            const notificationText = document.getElementById('notificationText');
            const forgotPasswordLink = document.getElementById('forgotPasswordLink');
            const forgotPasswordModal = document.getElementById('forgotPasswordModal');
            const closeModal = document.querySelector('.close-modal');
            const signupLink = document.getElementById('signupLink');
            
            // Ensure signup link works properly
            if (signupLink) {
                signupLink.addEventListener('click', function(e) {
                    // Allow default link behavior (navigation to signup.php)
                    // No need to prevent default or add any special handling
                    console.log('Navigating to signup page...');
                });
            }
            
            // Show suggestions when user ID input is focused
            userIdInput.addEventListener('focus', function() {
                userSuggestions.style.display = 'block';
            });
            
            // Hide suggestions when clicking outside
            document.addEventListener('click', function(e) {
                if (!userIdInput.contains(e.target) && !userSuggestions.contains(e.target)) {
                    userSuggestions.style.display = 'none';
                }
            });
            
            // Handle suggestion selection
            document.querySelectorAll('.autofill-suggestion').forEach(suggestion => {
                suggestion.addEventListener('click', function() {
                    const userId = this.getAttribute('data-user-id');
                    const userName = this.querySelector('.user-name').textContent;
                    
                    userIdInput.value = userId;
                    userSuggestions.style.display = 'none';
                    
                    // Show notification
                    showAutofillNotification(userName);
                    
                    // Focus on password field
                    passwordInput.focus();
                });
            });
            
            // Handle recent account selection
            recentAccounts.forEach(account => {
                account.addEventListener('click', function() {
                    const userId = this.getAttribute('data-user-id');
                    const userName = this.querySelector('.account-name').textContent;
                    const isLocked = this.classList.contains('account-locked');
                    
                    if (isLocked) {
                        alert('This account is currently locked. Please use the forgot password option to reset your password.');
                        return;
                    }
                    
                    userIdInput.value = userId;
                    
                    // Show notification
                    showAutofillNotification(userName);
                    
                    // Focus on password field
                    passwordInput.focus();
                });
            });
            
            // Show autofill notification
            function showAutofillNotification(userName) {
                notificationText.textContent = `User ID filled: ${userName}`;
                autofillNotification.classList.add('show');
                
                // Hide notification after 3 seconds
                setTimeout(() => {
                    autofillNotification.classList.remove('show');
                }, 3000);
            }
            
            // Form validation
            document.getElementById('signinForm').addEventListener('submit', function(e) {
                const userId = userIdInput.value.trim();
                const password = passwordInput.value;
                
                if (!userId || !password) {
                    e.preventDefault();
                    alert('Both User ID and Password are required.');
                    return;
                }
                
                // Validate user ID format (prefix followed by numbers)
                const userIdPattern = /^[A-Z]{3,4}-\d{6}$/;
                if (!userIdPattern.test(userId)) {
                    e.preventDefault();
                    alert('User ID must be in the correct format (e.g., INST-338445)');
                    return;
                }
            });

            // Confirm clear history
            document.getElementById('resetRecent')?.addEventListener('click', function(e) {
                if (!confirm('Are you sure you want to clear your recent login history?')) {
                    e.preventDefault();
                }
            });
            
            // Forgot password modal
            forgotPasswordLink.addEventListener('click', function(e) {
                e.preventDefault();
                forgotPasswordModal.style.display = 'block';
            });
            
            closeModal.addEventListener('click', function() {
                forgotPasswordModal.style.display = 'none';
            });
            
            window.addEventListener('click', function(e) {
                if (e.target === forgotPasswordModal) {
                    forgotPasswordModal.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>