<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';
require 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $otp = rand(100000, 999999); // Generate 6-digit OTP
    $otp_expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));

    // Clear any existing OTP for this email
    $clear_sql = "DELETE FROM users WHERE email = ?";
    $clear_stmt = $conn->prepare($clear_sql);
    $clear_stmt->bind_param("s", $email);
    $clear_stmt->execute();

    // Insert new OTP
    $sql = "INSERT INTO users (email, otp_code, otp_expiry) VALUES (?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sss", $email, $otp, $otp_expiry);
    
    if ($stmt->execute()) {
        // Debug output
        echo "OTP stored in database: $otp (expires: $otp_expiry)<br>";
        
        // Send email
        sendOtpEmail($email, $otp);
        
        // Redirect to verify page
        header("Location: verify.php?email=".urlencode($email));
        exit();
    } else {
        echo "Error: " . $stmt->error;
    }
}

function sendOtpEmail($email, $otp) {
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'mikylladaquing@gmail.com';
        $mail->Password   = 'jujt sedt qztd duzi';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        // Recipients
        $mail->setFrom('mikylladaquing@gmail.com', 'OTP Verification Script');
        $mail->addAddress($email);
        $mail->SMTPOptions = array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            )
        );

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your OTP Code';
        $mail->Body    = "Your OTP code is: <b>$otp</b><br><br>
                            The code will expire in 5 minutes.<br>
                            <a href='http://localhost/email/verify.php?email=".urlencode($email)."'>Click here to verify</a>";

        $mail->send();

        $mail->SMTPDebug = 2; // Enable verbose debug output
        $mail->Debugoutput = 'html'; // Output debug info as HTML
    } catch (Exception $e) {
        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    }
}
?>