# karanten

Grafikus, NVDA-val használható Windows program a Microsoft Defender karanténjának kezelésére. .NET 8, Windows Forms.

- Lista: fájlnév, eredeti hely, vírus/fenyegetés neve, időpont
- Visszaállítás a felhasználói mappában lévő `karanten` mappába
- Részletek: Enter vagy Részletek gomb
- Induláskor ellenőrzi a `karanten` és `karanten2` mappát: ha megvannak, nem csinál semmit; ha hiányzik, létrehozza, és a mappát meg a programot felveszi a Defender kivételei közé (WMI: `MSFT_MpPreference.Add`)
- `karanten2` üres marad
- Rendszergazdai jog kell, a program UAC-t kér

A kész `Karanten.exe` a GitHub Releases oldalon lesz, ha a `build-workflow.yml` fájl a `.github/workflows/` mappába kerül (ehhez a tokennek Workflows jogosultság kell). Nincs szükség parancssorra vagy fordítóra.

A karantén listázására és visszaállítására a Microsoft nem ad WMI/COM felületet; ezt a program a Defender saját MpCmdRun.exe-jével végzi háttérben, rejtett ablakkal.
