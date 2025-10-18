<?php
require_once 'db.php';
session_start();

// Redirect if already logged in
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === false) {
    header('Location: admindashboard.php');
    exit();
}

// Function to generate a unique admin ID
function generateAdminId($pdo)
{
    $unique = false;
    $admin_id = '';

    while (!$unique) {
        // Generate a random 6-digit number
        $random_number = str_pad(mt_rand(1, 999999), 6, '0', STR_PAD_LEFT);
        $admin_id = 'ADM-' . $random_number;

        // Check if this ID already exists
        $checkStmt = $pdo->prepare("SELECT admin_id FROM admin_users WHERE admin_id = ?");
        $checkStmt->execute([$admin_id]);

        if ($checkStmt->rowCount() === 0) {
            $unique = true;
        }
    }

    return $admin_id;
}

// Process form submission
$error = '';
$success = '';
$generated_admin_id = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $full_name = trim($_POST['full_name']);
    $email = trim($_POST['email']);

    // Validate inputs
    if (empty($username) || empty($password) || empty($confirm_password) || empty($full_name) || empty($email)) {
        $error = 'All fields are required.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } else {
        try {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT admin_id FROM admin_users WHERE username = ?");
            $stmt->execute([$username]);

            if ($stmt->rowCount() > 0) {
                $error = 'Username already exists. Please choose a different one.';
            } else {
                // Check if email already exists
                $stmt = $pdo->prepare("SELECT admin_id FROM admin_users WHERE email = ?");
                $stmt->execute([$email]);

                if ($stmt->rowCount() > 0) {
                    $error = 'Email address already registered.';
                } else {
                    // Hash password
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);

                    // Generate a unique admin ID
                    $admin_id = generateAdminId($pdo);
                    $generated_admin_id = $admin_id;

                    // Insert new admin (default role is 'admin')
                    $stmt = $pdo->prepare("INSERT INTO admin_users (admin_id, username, role, password_hash, full_name, email, created_at) VALUES (?, ?, 'admin', ?, ?, ?, NOW())");
                    $stmt->execute([$admin_id, $username, $password_hash, $full_name, $email]);

                    $success = 'Admin account created successfully! Your Admin ID is: <strong>' . $admin_id . '</strong>. You can now <a href="adminsignin.php?admin_id=' . $admin_id . '">login here</a>.';

                    // Clear form
                    $username = $full_name = $email = '';
                }
            }
        } catch (Exception $e) {
            error_log("Error creating admin account: " . $e->getMessage());
            $error = 'An error occurred during registration. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Signup - University Canteen Kiosk</title>
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

        .form-input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            font-size: 1rem;
            transition: var(--transition);
        }

        .form-input:focus {
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

        .input-with-icon .form-input {
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

        .password-strength {
            margin-top: 8px;
            height: 5px;
            border-radius: var(--radius);
            background: var(--light-gray);
            overflow: hidden;
        }

        .password-strength-meter {
            height: 100%;
            width: 0;
            transition: var(--transition);
        }

        .password-requirements {
            margin-top: 8px;
            font-size: 0.8rem;
            color: var(--secondary);
        }

        .requirement {
            display: flex;
            align-items: center;
            margin-bottom: 3px;
        }

        .requirement i {
            margin-right: 5px;
            font-size: 12px;
        }

        .requirement.met {
            color: var(--success);
        }

        .admin-id-display {
            display: flex;
            align-items: center;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 12px 15px;
            font-weight: 500;
            user-select: none;
        }

        .admin-id-prefix {
            color: var(--primary);
            font-weight: 600;
            margin-right: 5px;
        }

        .admin-id-value {
            color: var(--dark);
            font-weight: 600;
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
                <h1 class="card-title">Admin Registration</h1>
                <p class="card-subtitle">Create a new administrator account</p>
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
            <?php endif; ?>

            <form method="POST" action="">
                <div class="form-group">
                    <label for="full_name" class="form-label">Full Name</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user input-icon"></i>
                        <input type="text" id="full_name" name="full_name" class="form-input" placeholder="Enter your full name" value="<?php echo isset($full_name) ? htmlspecialchars($full_name) : ''; ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label for="email" class="form-label">Email Address</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope input-icon"></i>
                        <input type="email" id="email" name="email" class="form-input" placeholder="Enter your email" value="<?php echo isset($email) ? htmlspecialchars($email) : ''; ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label for="username" class="form-label">Username</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user-circle input-icon"></i>
                        <input type="text" id="username" name="username" class="form-input" placeholder="Choose a username" value="<?php echo isset($username) ? htmlspecialchars($username) : ''; ?>" required>
                    </div>
                </div>

                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock input-icon"></i>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Create a password" required>
                        <button type="button" class="password-toggle" id="password-toggle">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="password-strength">
                        <div class="password-strength-meter" id="password-strength-meter"></div>
                    </div>
                    <div class="password-requirements">
                        <div class="requirement" id="req-length">
                            <i class="fas fa-circle"></i>
                            <span>At least 8 characters</span>
                        </div>
                        <div class="requirement" id="req-uppercase">
                            <i class="fas fa-circle"></i>
                            <span>One uppercase letter</span>
                        </div>
                        <div class="requirement" id="req-number">
                            <i class="fas fa-circle"></i>
                            <span>One number</span>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label for="confirm_password" class="form-label">Confirm Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock input-icon"></i>
                        <input type="password" id="confirm_password" name="confirm_password" class="form-input" placeholder="Confirm your password" required>
                        <button type="button" class="password-toggle" id="confirm-password-toggle">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div id="password-match" class="password-requirements"></div>
                </div>

                <button type="submit" class="btn btn-primary">Create Account</button>
            </form>

            <div class="text-center mt-4">
                <p>Already have an account? <a href="adminsignin.php" class="btn-link">Sign in here</a></p>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('password');
            const confirmPasswordInput = document.getElementById('confirm_password');
            const passwordToggle = document.getElementById('password-toggle');
            const confirmPasswordToggle = document.getElementById('confirm-password-toggle');
            const passwordStrengthMeter = document.getElementById('password-strength-meter');
            const passwordMatch = document.getElementById('password-match');
            
            // Toggle password visibility
            function setupPasswordToggle(toggleButton, inputField) {
                toggleButton.addEventListener('click', function() {
                    if (inputField.type === 'password') {
                        inputField.type = 'text';
                        toggleButton.innerHTML = '<i class="fas fa-eye-slash"></i>';
                    } else {
                        inputField.type = 'password';
                        toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
                    }
                });
            }
            
            setupPasswordToggle(passwordToggle, passwordInput);
            setupPasswordToggle(confirmPasswordToggle, confirmPasswordInput);
            
            // Check password strength
            passwordInput.addEventListener('input', function() {
                const password = passwordInput.value;
                let strength = 0;
                
                // Check password requirements
                const hasLength = password.length >= 8;
                const hasUppercase = /[A-Z]/.test(password);
                const hasNumber = /[0-9]/.test(password);
                
                // Update requirement indicators
                document.getElementById('req-length').className = hasLength ? 'requirement met' : 'requirement';
                document.getElementById('req-uppercase').className = hasUppercase ? 'requirement met' : 'requirement';
                document.getElementById('req-number').className = hasNumber ? 'requirement met' : 'requirement';
                
                if (hasLength) strength += 33;
                if (hasUppercase) strength += 33;
                if (hasNumber) strength += 34;
                
                // Update strength meter
                passwordStrengthMeter.style.width = strength + '%';
                
                if (strength < 33) {
                    passwordStrengthMeter.style.background = '#dc3545'; // Weak
                } else if (strength < 66) {
                    passwordStrengthMeter.style.background = '#ffc107'; // Medium
                } else {
                    passwordStrengthMeter.style.background = '#28a745'; // Strong
                }
            });
            
            // Check password match
            confirmPasswordInput.addEventListener('input', function() {
                if (passwordInput.value !== confirmPasswordInput.value) {
                    passwordMatch.innerHTML = '<i class="fas fa-times-circle" style="color: #dc3545;"></i> Passwords do not match';
                } else {
                    passwordMatch.innerHTML = '<i class="fas fa-check-circle" style="color: #28a745;"></i> Passwords match';
                }
            });
        });
    </script>
</body>
</html>