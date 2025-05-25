<?php
require 'config.php';

// Check if user is verified
if (isset($_GET['email'])) {
    $email = trim($_GET['email']);
    $check_sql = "SELECT is_verified FROM users WHERE email = ?";
    $check_stmt = $conn->prepare($check_sql);
    $check_stmt->bind_param("s", $email);
    $check_stmt->execute();
    $result = $check_stmt->get_result();
    
    if ($result->num_rows > 0 && $result->fetch_assoc()['is_verified'] == 1) {
        // User is verified - show login form
        $check_stmt->close();
        $conn->close();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
        </head>
        <body>
            <h2>Welcome!</h2>
            <p>Your email <?php echo htmlspecialchars($email); ?> has been verified.</p>
            <!-- Add your login form here -->
            <form action="login.php" method="POST"></form>
                <input type="email" name="email" placeholder="Enter your email" required>
                <input type="password" name="password" placeholder="Enter your password" required>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        <?php
    } else {
        header("Location: index.php");
        exit();
    }
} else {
    header("Location: index.php");
    exit();
}


?>