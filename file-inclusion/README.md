<div align="center">
<h2>

Language Select

[Germany](#️-file-inclusion--php-beispiele-für-sicherheit--schwachstellen) | [Englisch](#️-file-inclusion--php-examples-for-security--vulnerabilities)

</h2>
</div>

---


# 🇩🇪 Deutsch

# 🛡️ File Inclusion – PHP Beispiele für Sicherheit & Schwachstellen

Dieses Repository enthält zwei PHP-Demomodule, die den Unterschied zwischen **unsicherer** und **sicherer** Dateieinbindung (File Inclusion) in Webanwendungen veranschaulichen.

---

## 🔍 Überblick

| Datei | Beschreibung |
|-------|--------------|
| [`module_unsafe.php`](examples/module_unsafe.php) | ❌ **Unsichere Dateieinbindung** – zeigt, wie direkte Benutzereingaben zu einer Local File Inclusion (LFI) Schwachstelle führen können. |
| [`module_safe.php`](examples/module_safe.php) | ✅ **Sichere Dateieinbindung** – nutzt eine Whitelist zur Validierung und schützt vor LFI-Angriffen. |

---

## 📁 Ordnerstruktur

```text
file-inclusion/
├── examples/
│   ├── module_unsafe.php      # Verwundbares Beispiel
│   ├── module_safe.php        # Sichere Alternative
├── file-inclusion-de.md       # Erklärung auf Deutsch
├── file-inclusion-en.md       # English explanation
└── README.md                  # Dieses Dokument
```

---

## 📘 Weiterführende Artikel

| English  | Germany |
|:---:|:---:|
| [File Inclusion - English Version](file-inclusion-en.md) | [File Inclusion - Deutsche Version](file-inclusion-en.md) |

--- 

## 🚀 Nutzung

Diese Beispiele können genutzt werden, um zu lernen:
- Wie LFI-Schwachstellen funktionieren
- Wie man solche Fehler in echten Anwendungen erkennen kann
- Wie man sich durch einfache Maßnamen wie Whistlisting schützen kann


> ⚠️ Hinweis: Diese Dateien sind ausschließlich zu Lernzwecken gedacht. <br> Setze niemals unsicheren Beispielcode in Produktivsystemen ein!

---

## 💡 Beispiel-Vergleich

#### ❌ Unsicherer Code (LFI-anfällig)

```php
<?php
// module_unsafe.php
$page = $_GET['seite']; // Keine Validierung!
include("pages/" . $page . ".php"); // LFI möglich!
?>
```

#### ✅ Sicherer Code (mit Whitelist)

```php
<?php
// module_safe.php
$allowed_pages = ['home', 'kontakt', 'statistik'];
$page = $_GET['seite'];

if (in_array($page, $allowed_pages)) {
    include("pages/" . $page . ".php");
} else {
    echo "Ungültige Seite!";
}
?>
```

---

## 📄 Lizenz

Dieses Projekt steht unter der **MIT License** -- siehe [LICENSE](../LICENSE)

```
MIT License

Copyright (c) 2025 daonware-it

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```


----

<div align="center">

# 🇬🇧 Englisch

</div>

# 🛡️ File Inclusion – PHP Examples for Security & Vulnerabilities

This repository contains two PHP demo modules that illustrate the difference between **unsafe** and **secure** file inclusion in web applications.

---

## 🔍 Overview

| File | Description |
|------|-------------|
| [`module_unsafe.php`](examples/module_safe.php) | ❌ **Unsafe file inclusion** – demonstrates how direct user input can lead to a Local File Inclusion (LFI) vulnerability. |
| [`module_safe.php`](examples/module_safe.php) | ✅ **Secure file inclusion** – uses a whitelist for validation and protects against LFI attacks. |

---

## 📁 Folder Structure

```text
file-inclusion/
├── examples/
│   ├── module_unsafe.php      # Vulnerable example
│   ├── module_safe.php        # Secure alternative
├── file-inclusion-de.md       # Explanation in German
├── file-inclusion-en.md       # English explanation
└── README.md                  # This document
```

---

## 📘 Further Reading

| English  | German |
|:---:|:---:|
| [File Inclusion - English Version](file-inclusion-en.md) | [File Inclusion - German Version](file-inclusion-en.md) |

---

## 🚀 Usage

These examples can be used to learn:
- How LFI vulnerabilities work
- How to identify such issues in real applications
- How to protect yourself using simple measures like whitelisting

> ⚠️ Note: These files are for educational purposes only. <br> Never use insecure example code in production systems!

---

## 💡 Example Comparison

#### ❌ Unsafe Code (LFI-vulnerable)

```php
<?php
// module_unsafe.php
$page = $_GET['seite']; // No validation!
include("pages/" . $page . ".php"); // LFI possible!
?>
```

#### ✅ Secure Code (with Whitelist)

```php
<?php
// module_safe.php
$allowed_pages = ['home', 'kontakt', 'statistik'];
$page = $_GET['seite'];

if (in_array($page, $allowed_pages)) {
    include("pages/" . $page . ".php");
} else {
    echo "Invalid page!";
}
?>
```

---

## 📄 License

This project is licensed under the **MIT License** -- watch [LICENSE](../LICENSE)

```
MIT License

Copyright (c) 2025 daonware-it

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```