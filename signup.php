<?php
// Include the database connection
include 'db.php';

// Initialize variables
$error = '';
$success = '';
$first_name = $last_name = $email = $phone = $college = $teaching_rank = '';

// Function to generate a unique user ID based on teaching rank
function generateUserId($pdo, $teaching_rank)
{
    $unique = false;
    $user_id = '';

    // Define prefix based on teaching rank
    $prefixes = [
        'instructor' => 'INST',
        'assistant' => 'ASST',
        'associate' => 'ASOC',
        'professor' => 'PROF',
        'university_professor' => 'UPRO'
    ];

    $prefix = $prefixes[$teaching_rank] ?? 'USER';

    while (!$unique) {
        // Generate a random 6-digit number
        $random_number = str_pad(mt_rand(1, 999999), 6, '0', STR_PAD_LEFT);
        $user_id = $prefix . '-' . $random_number;

        // Check if this ID already exists
        $checkStmt = $pdo->prepare("SELECT user_id FROM users WHERE user_id = ?");
        $checkStmt->execute([$user_id]);

        if ($checkStmt->rowCount() === 0) {
            $unique = true;
        }
    }

    return $user_id;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get form data
    $first_name = trim($_POST['first_name']);
    $last_name = trim($_POST['last_name']);
    $email = trim($_POST['email']);
    $phone = trim($_POST['phone']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);
    $college = trim($_POST['college']);
    $teaching_rank = trim($_POST['teaching_rank']);

    // Validate inputs
    if (empty($first_name) || empty($last_name) || empty($email) || empty($phone) || empty($password) || empty($confirm_password) || empty($college) || empty($teaching_rank)) {
        $error = 'All fields are required.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 8) {
        $error = 'Password must be at least 8 characters long.';
    } else {
        // Validate Philippine phone number format
        if (!preg_match('/^[9|8]\d{9}$/', $phone)) {
            $error = 'Please enter a valid Philippine phone number (e.g., 9123456789).';
        } else {
            try {
                // Check if email or phone already exists
                $checkStmt = $pdo->prepare("SELECT user_id FROM users WHERE email = ? OR phone = ?");
                $checkStmt->execute([$email, $phone]);

                if ($checkStmt->rowCount() > 0) {
                    $error = 'Email or Phone number already exists.';
                } else {
                    // Generate a unique user ID based on teaching rank
                    $user_id = generateUserId($pdo, $teaching_rank);

                    // Hash the password
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                    // Insert new user
                    $stmt = $pdo->prepare("INSERT INTO users (user_id, first_name, last_name, email, phone, password, college, teaching_rank) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

                    if ($stmt->execute([$user_id, $first_name, $last_name, $email, $phone, $hashed_password, $college, $teaching_rank])) {
                        $success = "Registration successful! Your User ID is: <strong>$user_id</strong>. You can now sign in.";
                        // Clear form
                        $first_name = $last_name = $email = $phone = $college = $teaching_rank = '';
                    } else {
                        $error = 'Registration failed. Please try again.';
                    }
                }
            } catch (PDOException $e) {
                $error = 'Database error: ' . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Sign Up - University CanteenKiosk</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #f88964;
            --secondary: #020c02ff;
            --dark: #333;
            --light: #f9f9f9;
            --gray: #777;
            --shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
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
            max-width: 500px;
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
        
        .input-with-icon input,
        .input-with-icon select {
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
        
        .user-id-display {
            display: flex;
            align-items: center;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 12px 15px;
            font-weight: 500;
            user-select: none;
        }
        
        .user-id-prefix {
            color: var(--primary);
            font-weight: 600;
            margin-right: 5px;
        }
        
        .user-id-value {
            color: var(--dark);
            font-weight: 600;
        }
        
        .phone-input-container {
            display: flex;
            align-items: center;
            position: relative;
            z-index: 1;
        }
        
        .country-code {
            padding: 12px 15px;
            background: #f0f0f0;
            border: 1px solid #ddd;
            border-right: none;
            border-radius: 8px 0 0 8px;
            font-weight: 500;
            user-select: none;
        }
        
        .phone-input {
            flex: 1;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 0 8px 8px 0;
            font-size: 1rem;
            transition: all 0.3s ease;
            padding-left: 15px;
            background-color: #fff !important;
            position: relative;
            z-index: 1;
        }
        
        .input-with-icon input:focus,
        .input-with-icon select:focus,
        .phone-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(248, 137, 100, 0.2);
            outline: none;
        }
        
        .error {
            color: #e74c3c;
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
            color: #27ae60;
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
        
        .success strong {
            display: block;
            margin-top: 5px;
            font-size: 1.1rem;
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
        
        button:active {
            transform: scale(0.98);
        }
        
        button i {
            margin-right: 8px;
        }
        
        .signin-link {
            text-align: center;
            margin-top: 20px;
            color: var(--gray);
            user-select: none;
        }
        
        .signin-link a {
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
        
        .signin-link a:hover {
            background: var(--primary);
            color: white;
            text-decoration: none;
        }
        
        .password-strength {
            margin-top: 5px;
            height: 5px;
            border-radius: 5px;
            background: #eee;
            overflow: hidden;
        }
        
        .password-strength-bar {
            height: 100%;
            width: 0;
            transition: width 0.3s, background 0.3s;
        }
        
        .phone-example {
            font-size: 0.8rem;
            color: var(--gray);
            margin-top: 5px;
            user-select: none;
        }
        
        /* Advanced anti-autofill techniques */
        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus,
        input:-webkit-autofill:active {
            -webkit-box-shadow: 0 0 0 30px white inset !important;
            box-shadow: 0 0 0 30px white inset !important;
            -webkit-text-fill-color: var(--dark) !important;
            transition: background-color 5000s ease-in-out 0s;
        }
        
        input:-internal-autofill-selected {
            background-color: white !important;
            color: var(--dark) !important;
        }
        
        /* Hide browser's autofill dropdown */
        input::-webkit-contacts-auto-fill-button,
        input::-webkit-credentials-auto-fill-button {
            visibility: hidden;
            display: none !important;
            pointer-events: none;
            position: absolute;
            right: -9999px;
        }
        
        /* Additional anti-autofill overlay */
        .anti-autofill-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: transparent;
            z-index: 2;
            pointer-events: none;
        }
        
        @media (max-width: 480px) {
            .card {
                padding: 20px;
            }
            
            .logo h1 {
                font-size: 2rem;
            }
            
            .input-with-icon i {
                left: 10px;
            }
            
            .input-with-icon input,
            .input-with-icon select {
                padding: 12px 15px 12px 40px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Canteen<span>Kiosk</span></h1>
            <p>University Food Ordering System</p>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2>Customer Sign Up</h2>
                <p>Create your account to order delicious food</p>
            </div>
            
            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success"><?php echo $success; ?></div>
            <?php endif; ?>
            
            <form method="post" action="" id="signupForm" autocomplete="off">
                <!-- Anti-autofill technique: Add hidden fields first -->
                <input type="text" name="prevent_autofill_username" style="display: none;" tabindex="-1" autocomplete="off">
                <input type="password" name="prevent_autofill_password" style="display: none;" tabindex="-1" autocomplete="off">
                
                <div class="form-group">
                    <label>User ID Preview</label>
                    <div class="user-id-display">
                        <span class="user-id-prefix" id="idPrefix">USER-</span>
                        <span class="user-id-value">######</span>
                    </div>
                    <small style="color: var(--gray); display: block; margin-top: 5px;">
                        <i class="fas fa-info-circle"></i> Your ID prefix will be based on your teaching rank
                    </small>
                </div>
                
                <div class="form-group">
                    <label for="teaching_rank">Teaching Rank</label>
                    <div class="input-with-icon">
                        <i class="fas fa-graduation-cap"></i>
                        <select id="teaching_rank" name="teaching_rank" required autocomplete="off" data-lpignore="true" data-form-type="other" onchange="updateIdPrefix()">
                            <option value="">Select Teaching Rank</option>
                            <option value="instructor" <?php echo ($teaching_rank == 'instructor') ? 'selected' : ''; ?>>Instructor</option>
                            <option value="assistant" <?php echo ($teaching_rank == 'assistant') ? 'selected' : ''; ?>>Assistant Professor</option>
                            <option value="associate" <?php echo ($teaching_rank == 'associate') ? 'selected' : ''; ?>>Associate Professor</option>
                            <option value="professor" <?php echo ($teaching_rank == 'professor') ? 'selected' : ''; ?>>Professor</option>
                            <option value="university_professor" <?php echo ($teaching_rank == 'university_professor') ? 'selected' : ''; ?>>University Professor</option>
                        </select>
                        <div class="anti-autofill-overlay"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="first_name">First Name</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" id="first_name" name="first_name" value="<?php echo htmlspecialchars($first_name); ?>" required placeholder="Enter your first name" autocomplete="off" autocapitalize="words" data-lpignore="true" data-form-type="other">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="last_name">Last Name</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" id="last_name" name="last_name" value="<?php echo htmlspecialchars($last_name); ?>" required placeholder="Enter your last name" autocomplete="off" autocapitalize="words" data-lpignore="true" data-form-type="other">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="email">Email</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required placeholder="Enter your email address" autocomplete="off" data-lpignore="true" data-form-type="other">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="phone">Phone Number (Philippines)</label>
                    <div class="phone-input-container">
                        <div class="country-code">+63</div>
                        <input type="tel" id="phone" name="phone" class="phone-input" value="<?php echo htmlspecialchars($phone); ?>" required placeholder="9123456789" pattern="[9|8][0-9]{9}" title="Please enter a valid Philippine phone number (e.g., 9123456789)" autocomplete="off" data-lpignore="true" data-form-type="other">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                    <div class="phone-example">Example: 9123456789 (without +63)</div>
                </div>
                
                <div class="form-group">
                    <label for="college">Colleges</label>
                    <div class="input-with-icon">
                        <i class="fas fa-building"></i>
                        <select id="college" name="college" required autocomplete="off" data-lpignore="true" data-form-type="other">
                            <option value="">Select College</option>
                            <option value="CTHM" <?php echo ($college == 'CTHM') ? 'selected' : ''; ?>>CTHM - College of Tourism and Hospitality Management</option>
                            <option value="CAS" <?php echo ($college == 'CAS') ? 'selected' : ''; ?>>CAS - College of Arts and Sciences</option>
                            <option value="CTE" <?php echo ($college == 'CTE') ? 'selected' : ''; ?>>CTE - College of Teacher Education</option>
                            <option value="CIT" <?php echo ($college == 'CIT') ? 'selected' : ''; ?>>CIT - College of Industrial Technology</option>
                            <option value="CCIT" <?php echo ($college == 'CCIT') ? 'selected' : ''; ?>>CCIT - College of Computing and Information Technologies</option>
                            <option value="CON" <?php echo ($college == 'CON') ? 'selected' : ''; ?>>CON - College of Nursing</option>
                            <option value="COE" <?php echo ($college == 'COE') ? 'selected' : ''; ?>>COE - College of Engineering</option>
                            <option value="CBAPA" <?php echo ($college == 'CBAPA') ? 'selected' : ''; ?>>CBAPA - College of Business Administration and Public Administration</option>
                            <option value="COL" <?php echo ($college == 'COL') ? 'selected' : ''; ?>>COL - College of Law</option>
                            <option value="COC" <?php echo ($college == 'COC') ? 'selected' : ''; ?>>COC - College of Communication</option>
                            <option value="CRIM" <?php echo ($college == 'CRIM') ? 'selected' : ''; ?>>CRIM - College of Criminology</option>
                            <option value="CCJ" <?php echo ($college == 'CCJ') ? 'selected' : ''; ?>>CCJ - College of Criminal Justice</option>
                            <option value="CAF" <?php echo ($college == 'CAF') ? 'selected' : ''; ?>>CAF - College of Accounting and Finance</option>
                        </select>
                        <div class="anti-autofill-overlay"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password (min 8 characters)</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" name="password" required placeholder="Enter your password" onkeyup="checkPasswordStrength()" autocomplete="new-password" data-lpignore="true">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                    <div class="password-strength">
                        <div class="password-strength-bar" id="passwordStrengthBar"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="confirm_password" name="confirm_password" required placeholder="Confirm your password" onkeyup="checkPasswordMatch()" autocomplete="new-password" data-lpignore="true">
                        <div class="anti-autofill-overlay"></div>
                    </div>
                    <small id="passwordMatch" style="display:none;color:#27ae60;"><i class="fas fa-check-circle"></i> Passwords match</small>
                    <small id="passwordNoMatch" style="display:none;color:#e74c3c;"><i class="fas fa-times-circle"></i> Passwords do not match</small>
                </div>
                
                <button type="submit"><i class="fas fa-user-plus"></i> Sign Up</button>
            </form>
            
            <div class="signin-link">
                <p>Already have an account?</p>
                <a href="signin.php"><i class="fas fa-sign-in-alt"></i> Sign In</a>
            </div>
        </div>
    </div>

    <script>
        // Update ID prefix based on teaching rank selection
        function updateIdPrefix() {
            const teachingRank = document.getElementById('teaching_rank').value;
            const idPrefix = document.getElementById('idPrefix');
            
            const prefixes = {
                'instructor': 'INST-',
                'assistant': 'ASST-',
                'associate': 'ASOC-',
                'professor': 'PROF-',
                'university_professor': 'UPRO-'
            };
            
            idPrefix.textContent = prefixes[teachingRank] || 'USER-';
        }
        
        // Add Philippines validation
        function validatePhilippinePhone(number) {
            // Philippine mobile numbers start with 9 or 8 followed by 9 digits
            const regex = /^[9|8]\d{9}$/;
            return regex.test(number.replace(/\s/g, ''));
        }
        
        function checkPasswordStrength() {
            const password = document.getElementById('password').value;
            const strengthBar = document.getElementById('passwordStrengthBar');
            let strength = 0;
            
            if (password.length >= 8) strength += 25;
            if (password.match(/[a-z]+/)) strength += 25;
            if (password.match(/[A-Z]+/)) strength += 25;
            if (password.match(/[0-9]+/)) strength += 25;
            
            strengthBar.style.width = strength + '%';
            
            if (strength < 50) {
                strengthBar.style.background = '#e74c3c';
            } else if (strength < 100) {
                strengthBar.style.background = '#f39c12';
            } else {
                strengthBar.style.background = '#27ae60';
            }
        }
        
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const match = document.getElementById('passwordMatch');
            const noMatch = document.getElementById('passwordNoMatch');
            
            if (confirmPassword.length === 0) {
                match.style.display = 'none';
                noMatch.style.display = 'none';
            } else if (password === confirmPassword) {
                match.style.display = 'block';
                noMatch.style.display = 'none';
            } else {
                match.style.display = 'none';
                noMatch.style.display = 'block';
            }
        }
        
        // Format phone number as user types
        document.getElementById('phone').addEventListener('input', function(e) {
            // Remove any non-digit characters
            let value = e.target.value.replace(/\D/g, '');
            
            // Limit to 10 digits
            if (value.length > 10) {
                value = value.slice(0, 10);
            }
            
            // Update the input value
            e.target.value = value;
        });
        
        // Form validation
        document.getElementById('signupForm').addEventListener('submit', function(e) {
            // Validate phone number
            const phone = document.getElementById('phone').value;
            if (!validatePhilippinePhone(phone)) {
                e.preventDefault();
                alert('Please enter a valid Philippine phone number (e.g., 9123456789). It should start with 9 or 8 and have 10 digits total.');
                return false;
            }
            
            // Validate teaching rank is selected
            const teachingRank = document.getElementById('teaching_rank').value;
            if (!teachingRank) {
                e.preventDefault();
                alert('Please select your teaching rank.');
                return false;
            }
            
            // Validate college is selected
            const college = document.getElementById('college').value;
            if (!college) {
                e.preventDefault();
                alert('Please select your college.');
                return false;
            }
        });

        // Advanced anti-autofill techniques
        document.addEventListener('DOMContentLoaded', function() {
            // Randomize field names on page load (will be reset before submit)
            const fields = document.querySelectorAll('input[name], select[name]');
            fields.forEach(field => {
                if (field.name !== 'first_name' && field.name !== 'last_name' && 
                    field.name !== 'email' && field.name !== 'phone' && 
                    field.name !== 'password' && field.name !== 'confirm_password' &&
                    field.name !== 'college' && field.name !== 'teaching_rank') {
                    const randomId = Math.random().toString(36).substring(2, 15);
                    field.setAttribute('name', 'field_' + randomId);
                }
            });
            
            // Reset field names before form submission
            document.getElementById('signupForm').addEventListener('submit', function() {
                document.querySelector('input[name="first_name"]').setAttribute('name', 'first_name');
                document.querySelector('input[name="last_name"]').setAttribute('name', 'last_name');
                document.querySelector('input[name="email"]').setAttribute('name', 'email');
                document.querySelector('input[name="phone"]').setAttribute('name', 'phone');
                document.querySelector('select[name="college"]').setAttribute('name', 'college');
                document.querySelector('select[name="teaching_rank"]').setAttribute('name', 'teaching_rank');
                document.querySelector('input[name="password"]').setAttribute('name', 'password');
                document.querySelector('input[name="confirm_password"]').setAttribute('name', 'confirm_password');
            });
            
            // Additional technique: Add a small delay before making fields visible
            setTimeout(function() {
                const inputs = document.querySelectorAll('input, select');
                inputs.forEach(input => {
                    input.style.opacity = '1';
                    input.style.transition = 'opacity 0.3s ease';
                });
            }, 100);
        });
    </script>
</body>
</html>