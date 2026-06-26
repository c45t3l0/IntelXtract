# IntelXtract

A single IntelX domain search can return whole breach/combolist files where the domain only appears incidentally: millions of unrelated credentials mixed with record IDs, phone numbers, dates and other non-credential junk. IntelXtract parses the export, keeps only real credentials tied to the domain, throws away the noise, deduplicates, and writes an organized workbook.

> It only re-organises data you already exported from IntelX, runs fully offline, and never uses the credentials for anything. Use it only on data you are authorised to process. **The output contains plaintext credentials, so treat it as sensitive data**.

## Features

- **Two worksheets**, split by who the leak belongs to:
  - **Professional Leaks**: the identity is an email on the searched domain (`someone@domain.com`).
  - **Personal Leaks**: users of the domain's application. The line points at the domain (login URL host on the domain, or the source breach is named after the domain) but the identity is a personal email / nickname (`someone@gmail.com`, `nick123`).
- **Keeps real credentials**: plaintext passwords **and** password hashes (MD5, SHA-1/224/256/384/512, bcrypt/argon2/sha-crypt).
- **Drops the garbage**: record GUIDs, MongoDB ObjectIds, dates/timestamps, phone numbers, IP addresses, monetary amounts, and structured non-credential tables (transaction dumps, company datasets, contact lists).
- **Deduplicated** on the `(identity, password)` pair, keeping the **oldest** occurrence; rows sorted newest leak first.
- **Scales to huge exports** (tens of millions of lines): streams file-by-file, sanitises characters Excel rejects, and spills any bucket that exceeds Excel's row limit to a companion CSV.
- **Optional flags** to export only professional or only personal leaks, and to dump unrelated credentials to a separate CSV.


## Requirements

- Python 3.9+
- [`openpyxl`](https://pypi.org/project/openpyxl/)

```bash
pip install openpyxl
```


## Usage

```bash
python intelxtract.py EXPORT_ZIP --domain example.com
```

### Options

| Flag | Description |
|------|-------------|
| `EXPORT_ZIP` | Path to the IntelX export `.zip` (required). |
| `-d`, `--domain` | Domain searched on IntelX (e.g. `example.com`). If omitted, it is inferred from the most common email domain (unreliable on large multi-breach exports). |
| `-o`, `--output` | Output `.xlsx` path. Default: `<zip name>_leaks.xlsx`. |
| `--include-unrelated` | Also export credentials **not** tied to the domain (co-resident in the exported dumps) to a separate CSV. Can be very large. |
| `--only-domain-emails` | Export only professional leaks. Mutually exclusive with `--only-personal-emails`. |
| `--only-personal-emails` | Export only personal leaks. Mutually exclusive with `--only-domain-emails`. |
| `-v`, `--verbose` | Verbose logging (shows which files are skipped and why). |

---

## Examples

**Standard run (recommended): scope everything to the domain:**
```bash
python intelxtract.py export.zip -d example.com
```

**Only emails on the domain (professional)**
```bash
python intelxtract.py export.zip -d example.com --only-domain-emails
```

**Only app users on the domain (personal)**
```bash
python intelxtract.py export.zip -d example.com --only-personal-emails
```

**Custom output path + verbose logging**
```bash
python intelxtract.py export.zip -d example.com -o report.xlsx -v
```

**Also dump everything NOT tied to the domain to a CSV**
```bash
python intelxtract.py export.zip -d example.com --include-unrelated
```

## How it works

### 1. Reading the export

IntelXtract opens the `.zip`, reads any index/metadata file inside it to recover each item's **leak name** and **date**, and then streams every content file. For files without metadata it falls back to the filename (and any date embedded in it), then the ZIP entry's timestamp.

### 2. Parsing credentials

Each file is parsed according to its shape:

- **Colon / free-form lines**: `email:password`, `url:email:password`, `url:user:password` (stealer-log style). The URL/host is captured for app-user detection.
- **Delimited tables (CSV/TSV/etc.)**: parsed only if they have a real **email column** *and* a real **password/hash column**. Structured datasets that merely list a domain (company directories, transaction dumps, contact lists) have no such pair and are skipped, so a slug, amount or phone number is never turned into a "password".
- **Header CSVs** with explicit `email`/`password` (or `hash`) columns are trusted directly.

### 3. What counts as a credential

**Kept** (real credentials):

- Plaintext passwords, including numeric ones (`12345678`).
- Password hashes: hex of a recognised hash length (32 = MD5/NTLM, 40 = SHA-1, 56, 64 = SHA-256, 96, 128 = SHA-512), and crypt strings (`$2a$...`, `$argon2...`, etc.).

**Excluded** (not credentials):

- Record GUIDs (`8-4-4-4-12` UUIDs), i.e. IntelX's own item IDs.
- Dates / timestamps (`2021-04-05T00:00:00.000Z`, `04/05/2021`).
- Phone numbers (formatted, 7 to 15 digits: `+17804581937`, `619.232.1378`, `(780) 458-1937`).
- IPv4 / IPv6 addresses.
- Monetary amounts (`4443.08`).

> Numeric values **without** any separator (e.g. `12345678`) are treated as possible passwords, so weak numeric passwords are not lost to the phone-number filter.

### 4. Domain classification

| Bucket | Condition |
|--------|-----------|
| **Professional** | Identity email is on the searched domain (or a subdomain). |
| **Personal (app user)** | The line's URL host is on the domain, or the source breach is named after the domain, and the identity is a personal email / username. |
| **Unrelated** | Neither the identity nor the URL touches the domain. Excluded by default. |

### 5. Dedup, sort, output

Credentials are deduplicated on `(identity, password)` (keeping the oldest occurrence) and sorted from newest leak to oldest.

---

## Output

A `.xlsx` workbook with up to three sheets:

- **Professional Leaks**
- **Personal Leaks**
- **Summary**: domain, counts per bucket, date range, top leaks, and notes.

Each leak sheet has the columns:

| Email / Username | Password | Leak Name | Leak Date | Source URL/Host |
|---|---|---|---|---|

### Companion CSV files

When a bucket is too large for a single Excel sheet (Excel caps at 1,048,576 rows), its full data is written next to the workbook and the sheet keeps a preview plus a pointer:

- `<output>_professional_leaks.csv` / `<output>_personal_leaks.csv`

With `--include-unrelated`, the unrelated credentials go to:

- `<output>_unrelated.csv`


## Notes & limitations

- The tool is **best-effort** on messy real-world dumps. The heuristics are tuned to avoid reporting junk as credentials. If a genuine credential format is being missed, or a new kind of non-credential value slips through, the relevant logic lives in `iter_credentials_from_text`, `parse_line`, `_iter_tabular` and the value classifiers (`_is_hash`, `_is_garbage`) near the top of the script and is easy to adjust.
- A domain email that appears in a breach **without** a password (e.g. an IntelX selector dump that only lists `GUID, email, date`) is **not** reported. By design, only entries with a real password/hash are kept.
- Output is **plaintext credential data**. Store, transfer and dispose of it accordingly.

Spotted a bug or have a credential format that's being missed? Ping me on [Twitter](https://x.com/c45t3l0)!
