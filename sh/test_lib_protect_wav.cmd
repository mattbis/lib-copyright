@echo off
setlocal
REM sh\test_lib_protect_wav.cmd
REM Verifies:
REM   1. test\res\sine_440hz.wav is generated and remains 100% byte-identical after protection
REM   2. The diff (protected - clean) is safe for Club / PA speaker systems (zero DC offset,
REM      zero infrasonic cone excursion <25 Hz, untouched sub-bass 25-120 Hz, safe HF horns >12 kHz)
REM   3. 64/64 CDMA provenance watermark bits are recovered with >5 sigma confidence

set "ROOT_DIR=%~dp0.."
python "%~dp0prototype_protect_wav.0.py" --test-sine "%ROOT_DIR%\test\res"
exit /b %ERRORLEVEL%
