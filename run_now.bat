@echo off
REM Manual on-demand run: double-click any time for an immediate digest.
REM Unlike run_6h.bat (hidden, cron-only, --hours 6 to match its 6h cadence),
REM this one stays visible and uses a 24h window so an ad-hoc run always
REM gives a full catch-up regardless of when it was last run.
cd /d "%~dp0"
"C:\Users\timot\AppData\Local\Programs\Python\Python313\python.exe" cve_watch.py --hours 24
echo.
pause
