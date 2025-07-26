<?php
function ladeModul($modulname) {
    $whitelist = ['dashboard', 'statistik', 'profil'];
    if (in_array($modulname, $whitelist)) {
        include("pages/" . $modulname . ".php");
    } else {
        echo "<p>Unerlaubter Modulzugriff.</p>";
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
        // ✅ Safe 
        ladeModul($seite);
        ?>
    </div>
</body>
</html>
