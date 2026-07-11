@echo off
sc create aegisd binPath= "C:\Program Files\Aegis\aegisd.exe -config C:\Program Files\Aegis\config.yaml" start= auto
sc start aegisd
