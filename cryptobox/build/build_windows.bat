@echo off
setlocal
cd /d "%~dp0.."

python -m pip install --upgrade pyinstaller || goto :error

python -m PyInstaller --noconfirm --onefile --windowed --name Cryptobox ^
  --workpath build\pyinstaller --distpath dist ^
  --add-data "cryptobox\data\common_passwords.txt;cryptobox\data" ^
  run_gui.py || goto :error

echo.
echo Built dist\Cryptobox.exe
goto :eof

:error
echo Build failed.
exit /b 1
