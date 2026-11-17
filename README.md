# MOU Portal

A small, temporary Flask app (run by the **Legal Unit**) for collecting regional
**Memoranda of Understanding**. Each region's representative registers, logs in, fills in
the MOU details **on the site**, downloads the **completed MOU** (generated as a PDF with
every field filled — only the signature/date lines are blank), signs it by hand, then
uploads the signed hardcopy (PDF) plus any supporting documents and submits. An
administrator (the boss) reviews who has submitted, downloads the completed/unsigned MOU and
the signed uploads (per file, CSV, or a single ZIP).

Mounted at **hrdnexus.org/mou** (same cPanel account as the UCP app). SQLite-backed — no
database to provision. PDF generation uses **fpdf2** (pure Python, no system libraries).

## Run locally

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows
pip install -r requirements.txt
python app.py init-db
python app.py create-admin boss@example.com "ChangeMe!" "Director, HRD"
python app.py                                     # http://127.0.0.1:5057
```

## The MOU document

The MOU is **generated on the fly** from the fields the representative fills in
(`build_mou_pdf` in `app.py`). It is a generic placeholder — edit the wording in that
function to substitute the official MOU text later. No template file to upload.

## Deploy to cPanel (hrdnexus.org/mou)

1. Push this repo, then on the server: `git clone` / `git pull` into `~/mou_portal`.
2. cPanel → **Setup Python App**:
   - Python 3.9, Application root `mou_portal`, **Application URL `mou`**
   - Startup file `passenger_wsgi.py`, Entry point `application`
3. Enter the app's virtualenv and install deps:
   ```bash
   pip install -r requirements.txt
   ```
4. Set an environment variable in the Python App panel: `MOU_SECRET_KEY` = a long random string.
5. Initialise and create the boss's admin account (in the app's venv, via Terminal):
   ```bash
   python app.py init-db
   python app.py create-admin boss@ghs.gov.gh "<password>" "Legal Unit"
   ```
6. **Restart** the app from the Python App panel.

### Notes
- `instance/` (the SQLite DB) and `uploads/` (submitted documents) hold live data and are
  gitignored, so `git pull` never overwrites them. Both must be writable by the app.
- Max upload size is 15 MB per file. Signed MOU = PDF only; supporting files = PDF/JPG/PNG.
- Admin tools: **Export CSV** (submission list) and **Download all documents (ZIP)**.
