@echo off
rem KB-Desk one-command launcher (Windows). Forwards to run.ps1.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
