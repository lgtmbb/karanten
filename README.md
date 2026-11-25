# karanten

Grafikus, NVDA-val használható Windows program a Microsoft Defender karanténjának kezelésére.

- Listában mutatja a karanténban lévő fájlokat: fájlnév, eredeti hely, vírus/fenyegetés neve, időpont
- Visszaállítás a felhasználói mappában lévő `karanten` mappába (`MpCmdRun -Restore -FilePath ... -Path ...`)
- Részletek (Enter vagy Részletek gomb): melyik vírus, honnan
- Induláskor ellenőrzi a `karanten` és `karanten2` mappát a felhasználói mappában: ha megvannak, nem csinál semmit; ha hiányzik, létrehozza, és a mappát meg a programot felveszi a Defender kivételei közé (`Add-MpPreference -ExclusionPath`)
- `karanten2` üres marad

Rendszergazdai jog kell; a program magát újraindítja emelt joggal (UAC).

Fordítás: `build.bat` (csak a Windows saját .NET Framework fordítója kell). A kész `Karanten.exe` a `release` mappában is megtalálható.
