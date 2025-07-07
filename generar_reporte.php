<?php
require __DIR__ . '/vendor/autoload.php';

use PhpOffice\PhpSpreadsheet\Spreadsheet;
use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($argc < 3) {
    die("Debe proporcionar el correo electrónico y la IP del objetivo como argumentos.\n");
}

$email = $argv[1];
$email = str_replace('--email=', '', $email);

$target_ip = $argv[2];
$target_ip = str_replace('--target_ip=', '', $target_ip);

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("El correo electrónico proporcionado no es válido.\n");
}

// ¡CAMBIA 'localhost' a la IP de tu máquina Kali!
$conn = pg_connect("host=192.168.81.128 dbname=gvmd user=postgres password=2014563"); 

if (!$conn) {
    die("Connection failed: " . pg_last_error());
}

$query = "
    SELECT r.host, r.hostname, r.port, n.cve, n.name AS vulnerability_name, r.severity, n.solution
    FROM results r
    JOIN nvts n ON r.nvt = n.oid
    WHERE r.host = '$target_ip'
    AND n.modification_time = (
        SELECT MAX(n2.modification_time)
        FROM nvts n2
        WHERE n2.oid = n.oid
    )
    ORDER BY r.host, r.port;
";

$result = pg_query($conn, $query);

if (!$result) {
    die("Error en la consulta: " . pg_last_error());
}

$spreadsheet = new Spreadsheet();
$sheet = $spreadsheet->getActiveSheet();

$sheet->setCellValue('A1', 'Host');
$sheet->setCellValue('B1', 'Port');
$sheet->setCellValue('C1', 'CVE');
$sheet->setCellValue('D1', 'Vulnerability Name');
$sheet->setCellValue('E1', 'Severity');
$sheet->setCellValue('F1', 'Solution');

$row = 2;
while ($row_data = pg_fetch_assoc($result)) {
    $sheet->setCellValue('A' . $row, $row_data['hostname']);
    $sheet->setCellValue('B' . $row, $row_data['port']);
    $sheet->setCellValue('C' . $row, $row_data['cve']);
    $sheet->setCellValue('D' . $row, $row_data['vulnerability_name']);
    $sheet->setCellValue('E' . $row, $row_data['severity']);
    $sheet->setCellValue('F' . $row, $row_data['solution']);
    $row++;
}

pg_close($conn);

$writer = new Xlsx($spreadsheet);

$filename = '/tmp/Vulnerabilidades_Detectadas_' . time() . '.xlsx';
$writer->save($filename);

$mail = new PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = 'frank11072001@gmail.com'; // Tus credenciales de Gmail
    $mail->Password   = 'shfxnyiwipbyfrur'; // Tu contraseña de aplicación de Gmail
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port       = 587;

    $mail->setFrom('frank11072001@gmail.com', 'MANUUUUUUUUUUUU');
    $mail->addAddress($email);

    $mail->isHTML(true);
    $mail->Subject = 'Reporte de Vulnerabilidades';
    $mail->Body    = 'Adjunto encontrarás el reporte de vulnerabilidades detectadas.';

    $mail->addAttachment($filename);

    $mail->send();

    echo 'El correo fue enviado correctamente.';
} catch (Exception $e) {
    echo "Hubo un error al enviar el correo. Error: {$mail->ErrorInfo}";
}

unlink($filename);
?>
