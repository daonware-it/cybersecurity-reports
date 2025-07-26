<?php
function ladeModul($modulname) {
    // Internes "Modul"-System des CMS
    $datei = "pages/" . $modulname . ".php";
    if (file_exists($datei)) {
        include($datei);
    } else {
        echo "<p>Modul nicht gefunden.</p>";
    }
}

$seite = $_GET['view'] ?? 'dashboard';

?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Adminbereich</title>
</head>
<body>
    <h1>Adminbereich – Modul: <?= htmlspecialchars($seite) ?></h1>
    <nav>
        <a href="?view=dashboard">Dashboard</a> |
        <a href="?view=statistik">Statistik</a> |
        <a href="?view=profil">Profil</a>
    </nav>
    <hr>

    <div class="inhalt">
        <?php
        // ❌ File Inclusion
        ladeModul($seite);
        ?>
    </div>
</body>
</html>
