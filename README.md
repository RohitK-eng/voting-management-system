# BallotDesk — Voting Management System

A polished Flask + SQLite voting management demo with a responsive admin workspace, modern sign-in and registration pages, voter/candidate records, ballot casting, election results, DDL operations and an SQL console.

## Run on Windows

1. Extract this ZIP.
2. Open the extracted `voting_management_system_professional` folder.
3. Click the File Explorer address bar, type `cmd`, and press Enter.
4. Install the dependency:

   ```cmd
   python -m pip install -r requirements.txt
   ```

5. Start the app:

   ```cmd
   python app.py
   ```

6. Open `http://127.0.0.1:5000` in your browser.

## Demo administrator

- Username: `admin`
- Password: `admin123`

After signing in, open **DDL Operations**, choose **Create voting tables**, and then **Load sample data**.

## Features

- Responsive BallotDesk visual identity with a dark gradient navigation rail, refined cards, status indicators, hover/focus states, and polished forms and tables.
- Dedicated sign-in and staff registration layouts that clearly identify the Voting Management System.
- Voter and candidate record management.
- One-voter-one-vote constraint and age validation (voters must be 18 or older).
- Live election result summary and turnout.
- SQLite DDL workspace and SQL console with a **Test only** rollback option.
- Data is stored locally in `voting.db`, created automatically next to `app.py`.

The interface loads DM Sans and Manrope from Google Fonts when internet access is available, with system-font fallbacks when offline.

## Important

This is a local academic demo, not a production election system. Change the demo credentials and configure a strong `SECRET_KEY` before exposing it beyond the local computer. Do not commit `voting.db` to GitHub.
