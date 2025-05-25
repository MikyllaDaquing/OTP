<?php
require 'config.php';

// Pre-fill email if coming from sent_otp.php
$email = isset($_GET['email']) ? trim($_GET['email']) : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify OTP</title>
</head>
<body>
    <h2>Verify Your OTP</h2>
    <form action="verify_otp.php" method="POST">
        <input type="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required readonly><br>
        <input type="text" name="otp" placeholder="Enter 6-digit OTP" required><br>
        <button type="submit">Verify</button>
    </form>
</body>
</html>