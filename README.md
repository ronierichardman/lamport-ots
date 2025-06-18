# Lamport Einmalsignatur Implementation

Diese Implementation der Lamport Einmalsignatur besteht aus drei C-Programmen für die Generierung von Schlüsselpaaren, das Signieren von Dokumenten und die Verifikation von Signaturen.

## Voraussetzungen

- OpenSSL-Bibliothek (libcrypto)
- GCC Compiler
- Linux/Unix-Umgebung

## Kompilierung

```bash
make all
```

Oder einzeln:
```bash
gcc -Wall -Wextra -std=c99 -g -I../is-prak55/openssl-3.5.0/include -o keygen-s89555 keygen-s89555.c -L../is-prak55/openssl-3.5.0 -lcrypto
gcc -Wall -Wextra -std=c99 -g -I../is-prak55/openssl-3.5.0/include -o sign-s89555 sign-s89555.c -L../is-prak55/openssl-3.5.0 -lcrypto
gcc -Wall -Wextra -std=c99 -g -I../is-prak55/openssl-3.5.0/include -o verify-s89555 verify-s89555.c -L../is-prak55/openssl-3.5.0 -lcrypto
```

## Verwendung

### 1. Schlüsselpaar generieren

```bash
./keygen-s89555
```

Erstellt die Dateien:
- `lamport-ots.pub` (öffentlicher Schlüssel, 644 Berechtigung)
- `lamport-ots.priv` (privater Schlüssel, 600 Berechtigung)

### 2. Dokument signieren

```bash
./sign-s89555 <dateiname>
```

Beispiel:
```bash
./sign-s89555 beispiel.txt
```

Erstellt die Signaturdatei `beispiel.txt.sign`.

### 3. Signatur verifizieren

```bash
./verify-s89555 <dateiname>
```

Beispiel:
```bash
./verify-s89555 beispiel.txt
```

Ausgabe:
- `VALID` bei gültiger Signatur (Rückgabewert 0)
- `INVALID` bei ungültiger Signatur (Rückgabewert 1)

## Funktionsweise

Die Lamport Einmalsignatur basiert auf:

1. **Schlüsselgenerierung**: Für jeden Bit des SHA-256 Hashs werden zwei 32-Byte Zufallswerte generiert (privater Schlüssel). Der öffentliche Schlüssel besteht aus den SHA-256 Hashes dieser Werte.

2. **Signierung**: Das Dokument wird mit SHA-256 gehasht. Für jeden Bit des Hashs wird der entsprechende private Schlüsselwert ausgewählt.

3. **Verifikation**: Jeder Signaturwert wird gehasht und mit dem entsprechenden öffentlichen Schlüsselwert verglichen.

## Sicherheitshinweise

- Der private Schlüssel sollte nur einmal verwendet werden (Einmalsignatur!)
- Die Datei `lamport-ots.priv` hat restriktive Berechtigungen (600)
- Bereits existierende Schlüsseldateien werden ohne Nachfrage überschrieben

## Tests

```bash
./test.sh
```

Führt umfassende Tests durch:
- Gültige Signatur
- Ungültige Signatur
- Fehlende Dateien
- Fehlerbehandlung

## Dateien

- `keygen-s89555.c` - Schlüsselgenerierung
- `sign-s89555.c` - Signaturerstellung  
- `verify-s89555.c` - Signaturverifikation
- `lamport.h` - Header-Datei mit Konstanten und Definitionen
- `Makefile` - Build-Konfiguration
- `test.sh` - Testskript
- `README.md` - Diese Dokumentation

## Implementierungsdetails

- SHA-256 für Hashing (256 Bit = 256 Schlüsselpaare)
- 32 Byte pro Schlüsselkomponente
- Hexadezimale Textdateien (nicht binär)
- RAND_priv_bytes() für Zufallszahlenerzeugung
- Robuste Fehlerbehandlung
