<?php
require_once 'db.php';
session_start();

// Initialize variables
$admin_accounts = [];
$error = '';
$success = '';
$forgot_password_success = '';
$max_attempts = 3;
$is_locked = false;
$remaining_attempts = $max_attempts;

// Debug session
error_log("Session status - admin_logged_in: " . (isset($_SESSION['admin_logged_in']) ? 'true' : 'false'));

// Check if admin is already logged in
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    // Verify the admin still exists in database and session is valid
    try {
        if (isset($_SESSION['admin_id'])) {
            $stmt = $pdo->prepare("SELECT admin_id, username, full_name, role FROM admin_users WHERE admin_id = ?");
            $stmt->execute([$_SESSION['admin_id']]);
            if ($stmt->rowCount() === 1) {
                $admin = $stmt->fetch(PDO::FETCH_ASSOC);

                // Verify session data matches database
                if (
                    $_SESSION['admin_username'] === $admin['username'] &&
                    $_SESSION['admin_full_name'] === $admin['full_name'] &&
                    $_SESSION['admin_role'] === $admin['role']
                ) {

                    // Session is valid, redirect to dashboard
                    header('Location: admindashboard.php');
                    exit();
                } else {
                    // Session data mismatch, destroy session
                    session_destroy();
                    session_start();
                }
            } else {
                // Admin no longer exists, destroy session
                session_destroy();
                session_start();
            }
        }
    } catch (Exception $e) {
        error_log("Error verifying admin session: " . $e->getMessage());
        // Continue with login page on error
    }
}

// Get all admin accounts from the database
try {
    $stmt = $pdo->prepare("SELECT admin_id, full_name, username FROM admin_users WHERE status = 'active' ORDER BY full_name");
    $stmt->execute();
    $admin_accounts = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    error_log("Error fetching admin accounts: " . $e->getMessage());
    $error = "Database connection error. Please try again later.";
}

// Check if admin_id is passed via GET (from successful signup)
$admin_id = isset($_GET['admin_id']) ? trim($_GET['admin_id']) : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle forgot password request
    if (isset($_POST['forgot_password'])) {
        $email = trim($_POST['email']);

        if (empty($email)) {
            $error = 'Please enter your email address.';
        } else {
            try {
                // Check if email exists in admin_users table
                $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE email = ? AND status = 'active'");
                $stmt->execute([$email]);
                $admin = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($admin) {
                    // Generate password reset token
                    $reset_token = bin2hex(random_bytes(32));
                    $expiry = date('Y-m-d H:i:s', strtotime('+1 hour'));

                    // Store token in database
                    $stmt = $pdo->prepare("UPDATE admin_users SET reset_token = ?, reset_expiry = ? WHERE email = ?");
                    $stmt->execute([$reset_token, $expiry, $email]);

                    // Clear login attempts for this admin
                    try {
                        $stmt = $pdo->prepare("DELETE FROM admin_login_attempts WHERE admin_id = ?");
                        $stmt->execute([$admin['admin_id']]);
                    } catch (Exception $e) {
                        error_log("Error clearing login attempts: " . $e->getMessage());
                    }

                    // Send reset email
                    $reset_link = "http://" . $_SERVER['HTTP_HOST'] . "/admin_reset_password.php?token=" . $reset_token;
                    $subject = "Admin Password Reset Request - University Canteen Kiosk";
                    $message = "Hello " . $admin['full_name'] . ",\n\n";
                    $message .= "You requested a password reset for your admin account. Click the link below to reset your password:\n";
                    $message .= $reset_link . "\n\n";
                    $message .= "This link will expire in 1 hour.\n\n";
                    $message .= "If you didn't request this, please ignore this email.\n\n";
                    $message .= "Best regards,\nUniversity Canteen Kiosk Team";

                    // Set email headers
                    $headers = "From: noreply@" . $_SERVER['HTTP_HOST'] . "\r\n";
                    $headers .= "Reply-To: noreply@" . $_SERVER['HTTP_HOST'] . "\r\n";
                    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

                    // Send the email
                    if (mail($email, $subject, $message, $headers)) {
                        $forgot_password_success = "Password reset instructions have been sent to your email.";
                    } else {
                        $error = 'Failed to send email. Please try again or contact support.';
                        error_log("Email sending failed for: " . $email);
                    }
                } else {
                    $error = 'No active admin account found with that email address.';
                }
            } catch (Exception $e) {
                error_log("Error during admin password reset: " . $e->getMessage());
                $error = 'An error occurred. Please try again.';
            }
        }
    } else {
        // Handle regular login
        $admin_id = trim($_POST['admin_id']);
        $password = $_POST['password'];

        // Validate inputs
        if (empty($admin_id) || empty($password)) {
            $error = 'Admin ID and password are required.';

            // Log failed attempt (missing credentials)
            logLoginAttempt($pdo, $admin_id, '', false, 'Missing credentials');
        } else {
            try {
                // Check if admin is locked out
                try {
                    $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM admin_login_attempts WHERE admin_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE) AND success = 'failed'");
                    $stmt->execute([$admin_id]);
                    $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
                    $login_attempts = (int) $attempts_data['attempts'];
                } catch (Exception $e) {
                    error_log("Error checking login attempts: " . $e->getMessage());
                    $login_attempts = 0;
                }

                if ($login_attempts >= $max_attempts) {
                    $error = 'Too many failed attempts for this account. Please use the forgot password option to reset your password.';
                    $is_locked = true;
                } else {
                    // Check if admin exists and is active
                    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE admin_id = ? AND status = 'active'");
                    $stmt->execute([$admin_id]);

                    if ($stmt->rowCount() === 1) {
                        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
                        $username = $admin['username'];

                        // Log login attempt (start with failure assumption)
                        $attempt_id = logLoginAttempt($pdo, $admin_id, $username, false, 'Pending verification');

                        // Verify password
                        if (password_verify($password, $admin['password_hash'])) {
                            // Update login attempt to success
                            updateLoginAttempt($pdo, $attempt_id, true, 'Success');

                            // Clear all failed attempts for this admin
                            try {
                                $stmt = $pdo->prepare("DELETE FROM admin_login_attempts WHERE admin_id = ? AND success = 'failed'");
                                $stmt->execute([$admin_id]);
                            } catch (Exception $e) {
                                error_log("Error clearing failed attempts: " . $e->getMessage());
                            }

                            // Set session variables
                            $_SESSION['admin_logged_in'] = true;
                            $_SESSION['admin_id'] = $admin['admin_id'];
                            $_SESSION['admin_username'] = $admin['username'];
                            $_SESSION['admin_role'] = $admin['role'];
                            $_SESSION['admin_full_name'] = $admin['full_name'];
                            $_SESSION['login_time'] = time();

                            // Set success message with name and admin ID
                            $success = 'Welcome, ' . $admin['full_name'] . '! (Admin ID: ' . $admin['admin_id'] . ')';

                            // Redirect to dashboard after a brief delay
                            echo '<script>
                                setTimeout(function() {
                                    window.location.href = "admindashboard.php";
                                }, 2000);
                            </script>';
                        } else {
                            // Update login attempt to failure
                            updateLoginAttempt($pdo, $attempt_id, false, 'Invalid password');

                            // Get updated attempt count
                            try {
                                $stmt = $pdo->prepare("SELECT COUNT(*) as attempts FROM admin_login_attempts WHERE admin_id = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE) AND success = 'failed'");
                                $stmt->execute([$admin_id]);
                                $attempts_data = $stmt->fetch(PDO::FETCH_ASSOC);
                                $login_attempts = (int) $attempts_data['attempts'];
                                $remaining_attempts = max(0, $max_attempts - $login_attempts);
                            } catch (Exception $e) {
                                error_log("Error getting attempt count: " . $e->getMessage());
                                $remaining_attempts = $max_attempts - 1;
                            }

                            if ($login_attempts >= $max_attempts) {
                                $error = 'Too many failed attempts for this account. Please use the forgot password option to reset your password.';
                                $is_locked = true;
                            } else {
                                $error = 'Invalid password. ' . $remaining_attempts . ' attempt(s) remaining for this account.';
                            }
                        }
                    } else {
                        // Log failed attempt (admin not found or inactive)
                        logLoginAttempt($pdo, $admin_id, '', false, 'Admin ID not found or inactive');
                        $error = 'Admin ID not found or account is inactive.';
                    }
                }
            } catch (Exception $e) {
                error_log("Error during admin login: " . $e->getMessage());
                $error = 'An error occurred during login. Please check your credentials and try again.';

                // Log failed attempt (system error)
                logLoginAttempt($pdo, $admin_id, '', false, 'System error: ' . $e->getMessage());
            }
        }
    }
}

/**
 * Log a login attempt to the database
 */
function logLoginAttempt($pdo, $admin_id, $username, $success, $reason)
{
    try {
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

        $stmt = $pdo->prepare("
            INSERT INTO admin_login_attempts 
            (admin_id, username, attempt_time, ip_address, user_agent, success, failure_reason, created_at) 
            VALUES (?, ?, NOW(), ?, ?, ?, ?, NOW())
        ");

        $success_flag = $success ? 'successful' : 'failed';
        $stmt->execute([$admin_id, $username, $ip_address, $user_agent, $success_flag, $reason]);

        return $pdo->lastInsertId();
    } catch (Exception $e) {
        error_log("Error logging login attempt: " . $e->getMessage());
        return null;
    }
}

/**
 * Update an existing login attempt record
 */
function updateLoginAttempt($pdo, $attempt_id, $success, $reason)
{
    if (!$attempt_id)
        return false;

    try {
        $stmt = $pdo->prepare("
            UPDATE admin_login_attempts 
            SET success = ?, failure_reason = ? 
            WHERE attempt_id = ?
        ");

        $success_flag = $success ? 'successful' : 'failed';
        $stmt->execute([$success_flag, $reason, $attempt_id]);

        return true;
    } catch (Exception $e) {
        error_log("Error updating login attempt: " . $e->getMessage());
        return false;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Signin - University Canteen Kiosk</title>
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
            align-items: center;
            justify-content: center;
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

        .logo-icon {
            width: 70px;
            height: 70px;
            background: var(--primary);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
            color: white;
            font-size: 28px;
        }

        .logo-text {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .logo-text .canteen {
            color: var(--primary);
        }

        .logo-text .kiosk {
            color: var(--dark);
        }

        .tagline {
            color: var(--secondary);
            font-size: 1rem;
            margin-top: 5px;
        }

        .card {
            background: white;
            border-radius: var(--radius);
            padding: 30px;
            box-shadow: var(--shadow);
        }

        .card-header {
            text-align: center;
            margin-bottom: 25px;
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--dark);
            margin-bottom: 5px;
        }

        .card-subtitle {
            color: var(--secondary);
            font-size: 0.9rem;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark);
        }

        .form-input, .form-select {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
            transition: var(--transition);
        }

        .form-input:focus, .form-select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(235, 108, 30, 0.1);
        }

        .input-with-icon {
            position: relative;
        }

        .input-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--secondary);
        }

        .input-with-icon .form-input, .input-with-icon .form-select {
            padding-left: 45px;
        }

        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--secondary);
            cursor: pointer;
        }

        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: var(--radius);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
        }

        .btn-secondary {
            background: var(--secondary);
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .btn-link {
            background: none;
            color: var(--primary);
            text-decoration: underline;
            padding: 0;
            font-weight: 500;
        }

        .btn-link:hover {
            color: var(--primary-dark);
        }

        .alert {
            padding: 12px 15px;
            border-radius: var(--radius);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }

        .alert-error {
            background: rgba(220, 53, 69, 0.15);
            color: var(--danger);
            border: 1px solid rgba(220, 53, 69, 0.2);
        }

        .alert-success {
            background: rgba(40, 167, 69, 0.15);
            color: var(--success);
            border: 1px solid rgba(40, 167, 69, 0.2);
        }

        .alert-info {
            background: rgba(23, 162, 184, 0.15);
            color: var(--info);
            border: 1px solid rgba(23, 162, 184, 0.2);
        }

        .alert-warning {
            background: rgba(255, 193, 7, 0.15);
            color: var(--warning);
            border: 1px solid rgba(255, 193, 7, 0.2);
        }

        .alert-icon {
            margin-right: 10px;
            font-size: 18px;
        }

        .text-center {
            text-align: center;
        }

        .mt-3 {
            margin-top: 15px;
        }

        .mt-4 {
            margin-top: 20px;
        }

        .admin-id-note {
            font-size: 0.85rem;
            color: var(--secondary);
            margin-top: 5px;
        }

        .welcome-message {
            text-align: center;
            font-weight: 600;
            color: var(--success);
            margin: 15px 0;
            padding: 10px;
            background-color: rgba(40, 167, 69, 0.1);
            border-radius: var(--radius);
            border: 1px solid rgba(40, 167, 69, 0.2);
        }

        .account-locked-message {
            color: var(--danger);
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

        .attempts-warning {
            color: var(--warning);
            font-size: 0.85rem;
            margin-top: 5px;
            display: block;
            text-align: center;
            padding: 8px;
            background: rgba(255, 193, 7, 0.1);
            border-radius: 5px;
            margin-bottom: 10px;
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
            border-radius: var(--radius);
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

        @media (max-width: 480px) {
            .card {
                padding: 20px;
            }
            
            .logo-text {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <!-- Forgot Password Modal -->
    <div id="forgotPasswordModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <div class="modal-header">
                <h3><i class="fas fa-key"></i> Reset Admin Password</h3>
            </div>
            <?php if (!empty($forgot_password_success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle alert-icon"></i>
                    <?php echo $forgot_password_success; ?>
                </div>
            <?php endif; ?>
            <form method="post" id="forgotPasswordForm">
                <div class="form-group">
                    <label for="email" class="form-label">Admin Email Address</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope input-icon"></i>
                        <input type="email" id="email" name="email" class="form-input" required placeholder="Enter your admin email address">
                    </div>
                </div>
                <button type="submit" name="forgot_password" class="btn btn-primary">
                    <i class="fas fa-paper-plane"></i> Send Reset Link
                </button>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-utensils"></i>
            </div>
            <div class="logo-text">
                <span class="canteen">Canteen</span><span class="kiosk">Kiosk</span>
            </div>
            <p class="tagline">University Food Service Management System</p>
        </div>

        <div class="card">
            <div class="card-header">
                <h1 class="card-title">Admin Sign In</h1>
                <p class="card-subtitle">Select your account and enter your password</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle alert-icon"></i>
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle alert-icon"></i>
                    <?php echo $success; ?>
                </div>
                <div class="welcome-message">
                    <p>Redirecting to dashboard...</p>
                </div>
            <?php else: ?>
            <form method="POST" action="" id="adminLoginForm">
                <div class="form-group">
                    <label for="admin_id" class="form-label">Select Admin Account</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user input-icon"></i>
                        <select id="admin_id" name="admin_id" class="form-select" required <?php echo $is_locked ? 'disabled' : ''; ?>>
                            <option value="">-- Select your account --</option>
                            <?php foreach ($admin_accounts as $account): ?>
                                <option value="<?php echo $account['admin_id']; ?>" <?php echo ($admin_id === $account['admin_id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($account['full_name'] . ' (' . $account['admin_id'] . ')'); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <p class="admin-id-note">Select your account from the list</p>
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock input-icon"></i>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Enter your password" required <?php echo $is_locked ? 'disabled' : ''; ?>>
                        <button type="button" class="password-toggle" id="password-toggle" <?php echo $is_locked ? 'disabled' : ''; ?>>
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>

                <?php if ($is_locked): ?>
                    <div class="account-locked-message">
                        <i class="fas fa-lock"></i> This account has been locked due to too many failed attempts.
                    </div>
                <?php elseif ($remaining_attempts < $max_attempts && $remaining_attempts > 0): ?>
                    <div class="attempts-warning">
                        <i class="fas fa-exclamation-triangle"></i> <?php echo $remaining_attempts; ?> attempt(s) remaining before account lock.
                    </div>
                <?php endif; ?>

                <button type="submit" class="btn btn-primary" <?php echo $is_locked ? 'disabled' : ''; ?>>
                    <i class="fas fa-sign-in-alt"></i> Sign In
                </button>
            </form>

            <div class="text-center mt-4">
                <p>Don't have an account? <a href="adminsignup.php" class="btn-link">Sign up here</a></p>
                <?php if ($is_locked): ?>
                    <div class="alert alert-warning mt-3">
                        <i class="fas fa-lock alert-icon"></i>
                        Account locked. Please use the forgot password option to reset your password.
                    </div>
                <?php endif; ?>
                <p class="mt-3"><a href="#" id="forgotPasswordLink" class="btn-link">Forgot Password?</a></p>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('password');
            const passwordToggle = document.getElementById('password-toggle');
            const forgotPasswordLink = document.getElementById('forgotPasswordLink');
            const forgotPasswordModal = document.getElementById('forgotPasswordModal');
            const closeModal = document.querySelector('.close-modal');
            
            // Toggle password visibility
            if (passwordToggle) {
                passwordToggle.addEventListener('click', function() {
                    if (passwordInput.type === 'password') {
                        passwordInput.type = 'text';
                        passwordToggle.innerHTML = '<i class="fas fa-eye-slash"></i>';
                    } else {
                        passwordInput.type = 'password';
                        passwordToggle.innerHTML = '<i class="fas fa-eye"></i>';
                    }
                });
            }

            // Auto-focus password field when an account is selected
            const adminSelect = document.getElementById('admin_id');
            if (adminSelect) {
                adminSelect.addEventListener('change', function() {
                    if (this.value) {
                        passwordInput.focus();
                    }
                });
            }

            // Forgot password modal
            if (forgotPasswordLink) {
                forgotPasswordLink.addEventListener('click', function(e) {
                    e.preventDefault();
                    forgotPasswordModal.style.display = 'block';
                });
            }

            if (closeModal) {
                closeModal.addEventListener('click', function() {
                    forgotPasswordModal.style.display = 'none';
                });
            }

            window.addEventListener('click', function(e) {
                if (e.target === forgotPasswordModal) {
                    forgotPasswordModal.style.display = 'none';
                }
            });
        });
    </script>
</body>
</html>