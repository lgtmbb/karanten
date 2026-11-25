# Karanten.exe changelog

## Latest
- Fix: quarantine list was empty; the parser no longer depends on English labels, every MpCmdRun.exe copy is tried, and Defender protection history (WMI) is used as a fallback
- Restore success is now checked by the file appearing in the karanten folder
- Quarantine list with the buttons beside it, reachable with Tab: Visszaállítás, Részletek, Frissítés, Nyers kimenet, Mappa megnyitása, Súgó, Kilépés
- Részletek window: file name, previous location, full path, virus name and type, Defender category and severity, active or not, quarantine time
- Súgó (F1 or Alt+S): read-only text box describing every function
- Restore goes to the karanten folder in the user folder
- On every start the karanten and karanten2 folders are checked; missing ones are created and added to the Defender exclusions together with the program
- Exclusions are set through Defender's WMI interface, no PowerShell or cmd
- Needs administrator rights (UAC prompt)
- Release now also contains Karanten-teljes-program.zip: exe, Help.txt, README, changelog and the full source
