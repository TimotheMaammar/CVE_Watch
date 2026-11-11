@echo off
REM 6-hourly wrapper for Task Scheduler: runs the CVE watch (NVD + GitHub
REM Advisories + CISA KEV, plus GitHub Advisories as its own section) and
REM logs to a dated file, since a scheduled run has no console to watch.
REM --hours 6 matches the 6h cron interval exactly (no overlap margin).
REM Launched hidden via run_hidden.vbs — don't point the task at this .bat
REM directly or a console window flashes up each run.
cd /d "%~dp0"
set LOGDIR=_logs
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
REM %date% is locale-dependent (its field order/format changes with Windows'
REM regional settings), so build the log filename via PowerShell's
REM culture-invariant Get-Date -Format instead.
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set LOGDATE=%%i
REM Explicit python.exe path, not bare "python" — avoids depending on PATH
REM resolution order under Task Scheduler's own environment.
"C:\Users\timot\AppData\Local\Programs\Python\Python313\python.exe" cve_watch.py --hours 6 >> "%LOGDIR%\run_log_%LOGDATE%.txt" 2>&1
