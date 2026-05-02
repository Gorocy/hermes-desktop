# SHA-256 hashes — instrukcja VirusTotal lookup

Date: 2026-05-02 | Project: hermes-desktop | Files hashed: 36 | Unique hashes: 34

## Jak sprawdzić w VT website

1. Otwórz: https://www.virustotal.com/gui/home/search
2. Wklej pojedynczy SHA-256 hash w pole search
3. Czytaj wynik:
   - **Brak detekcji + "First seen" odlegle w przeszłości** = OK (znana, czysta paczka)
   - **Wiele detekcji jako "trojan/malware"** = ALARM, sprawdź dokładnie nazwy detekcji
   - **"Item not found"** dla `better_sqlite3.node` = NORMAL (świeży local build)
   - **"Item not found"** dla innych = warto upload pliku do skanu (free, anonymous)

## Alternatywne batch services (bez API key)
- **MetaDefender Cloud** (https://metadefender.com/scan) — 30+ engines, free, batch hash search
- **Hybrid Analysis** (https://hybrid-analysis.com) — wymaga konta, free tier
- **VirusTotal GUI Pro** — batch search, ale paid

## PRIORYTET 1 — natywne moduły npm (oficjalne prebuilds)

| SHA-256 | Size | Package | Files |
|---|---|---|---|
| `6ac4ba1cce8aca75dbcafafa1951955d…` | 8.1 MB | lightningcss-darwin-arm64 | lightningcss-darwin-arm64/lightningcss.darwin-arm64.node |
| `1bcf76c8b79b48791ed0f415a43de16b…` | 2.8 MB | @tailwindcss/oxide-darwin-arm64 | @tailwindcss/oxide-darwin-arm64/tailwindcss-oxide.darwin-arm64.node |
| `22e58d68e099a783491dc358e4e75d4e…` | 1.7 MB | @rollup/rollup-darwin-arm64 | @rollup/rollup-darwin-arm64/rollup.darwin-arm64.node |
| `182edb49efc39a8f9df3a73e8f24cd18…` | 207 KB | iconv-corefoundation/lib | iconv-corefoundation/lib/native.node |
| `40f2f51199e4f5fc46fa6b985fb3461b…` | 160 KB | fsevents | fsevents/fsevents.node |

Pełne hashe (do wklejenia):
```
22e58d68e099a783491dc358e4e75d4ef5d1fdf75c14856366848ff72fab1791
1bcf76c8b79b48791ed0f415a43de16b84c8e96132ef44dde7771078bba913aa
40f2f51199e4f5fc46fa6b985fb3461bb63e6cd86c62bfa9bcee45ed4438d5fb
182edb49efc39a8f9df3a73e8f24cd185bcc948197480c55adc7acda04af6ae3
6ac4ba1cce8aca75dbcafafa1951955dd30d99ca9953fa81020d0c5246cbd317
```

## PRIORYTET 2 — bundlowane installer tooling (Squirrel + electron-builder)

| SHA-256 | Size | Package | Files |
|---|---|---|---|
| `e101932f5685b8e7d5e81ccb132f245e…` | 23.5 MB | app-builder-bin/win | app-builder-bin/win/x64/app-builder.exe |
| `98d3d9a42ef4148efdf86d664c63c89f…` | 22.6 MB | app-builder-bin/win | app-builder-bin/win/arm64/app-builder.exe |
| `b92d23d7847e2d5c6031e63537bd89e5…` | 22.3 MB | app-builder-bin/win | app-builder-bin/win/ia32/app-builder.exe |
| `76359cd4b0349a83337b941332ad042c…` | 1.8 MB | electron-winstaller/vendor | electron-winstaller/vendor/Squirrel.exe |
| `c2a2c78e0912a6576517fc69ffd32793…` | 1.8 MB | electron-winstaller/vendor | electron-winstaller/vendor/SyncReleases.exe |
| `81591699f7f156dc15f4e188fd132e01…` | 1.8 MB | electron-winstaller/vendor | electron-winstaller/vendor/Squirrel-Mono.exe |
| `d823e6d954f7e445fbbb5c04e40a39cf…` | 282 KB | electron-winstaller/vendor | electron-winstaller/vendor/StubExecutable.exe |
| `1e47eb606dad4c5c1568cfb8f4e970e1…` | 218 KB | electron-winstaller/vendor | electron-winstaller/vendor/Setup.exe |
| `e2df7b664db830f159d0dc6b3da8a954…` | 149 KB | electron-winstaller/vendor | electron-winstaller/vendor/rcedit.exe |
| `9dfae44e99488add680ae6f7801283d4…` | 113 KB | electron-winstaller/vendor | electron-winstaller/vendor/winterop.dll |
| `9278fe28ac434fde0be3a10788dc13ad…` | 110 KB | electron-winstaller/vendor | electron-winstaller/vendor/WriteZipToSetup.exe |
| `490e29aa66c82487f79412df651c9e2a…` | 20 KB | electron-winstaller/vendor | electron-winstaller/vendor/wconsole.dll |

Pełne hashe (do wklejenia):
```
98d3d9a42ef4148efdf86d664c63c89f1d221d7122878a6298071de5d0d8b141
b92d23d7847e2d5c6031e63537bd89e56f6a98ee112baa90258dc664240a17d7
e101932f5685b8e7d5e81ccb132f245e4227065608a86673397b1c70a05e989f
e2df7b664db830f159d0dc6b3da8a95442cca175b9577f2d19952646d37ac32f
1e47eb606dad4c5c1568cfb8f4e970e1051ba5806aedb1ff3256284a8280d83b
81591699f7f156dc15f4e188fd132e01369352043511e758513dba59b19ac920
76359cd4b0349a83337b941332ad042c90351c2bb0a4628307740324c97984cc
d823e6d954f7e445fbbb5c04e40a39cf248a3621f9eccbafdf3f0f1e7acb11dd
c2a2c78e0912a6576517fc69ffd32793134f1a5b2b066279de3757c76c501548
490e29aa66c82487f79412df651c9e2a34d764fdf0b00b76944b63e9e6b780e3
9dfae44e99488add680ae6f7801283d45898baf48a7486c2a1adf8c105f6941d
9278fe28ac434fde0be3a10788dc13ad92a28940ed70a52f86d9d69435599349
```

## PRIORYTET 3 — znane tooling (Microsoft / 7-Zip / WiX) — większość engine'ów rozpozna jako benign

| SHA-256 | Size | Package | Files |
|---|---|---|---|
| `4b3cf980a840f3e36d98fef3b4d4c302…` | 1.7 MB | electron-winstaller/vendor | electron-winstaller/vendor/wix.dll |
| `61704f7dbe233980992f2a00ef9baacf…` | 1.6 MB | electron-winstaller/vendor | electron-winstaller/vendor/nuget.exe |
| `9ed007aa82e440ceb39a6e105bb1d602…` | 1.5 MB | electron-winstaller/vendor | electron-winstaller/vendor/7z-x64.dll |
| `c167dbedd388718c70c921eeeac82549…` | 1.5 MB | electron-winstaller/vendor | electron-winstaller/vendor/7z-arm64.dll<br>electron-winstaller/vendor/7z.dll |
| `b0cfdeaf429f5cc53f85123dd8f5a5fe…` | 1.2 MB | 7zip-bin/win | 7zip-bin/win/x64/7za.exe |
| `81f67048b7366870e5d49f00a8c57057…` | 1.0 MB | 7zip-bin/win | 7zip-bin/win/arm64/7za.exe |
| `31fd52f8996986623cf52c3b4d0f7ac7…` | 774 KB | 7zip-bin/win | 7zip-bin/win/ia32/7za.exe |
| `65d0dcc70753ff3efd4631ac784d35ea…` | 476 KB | electron-winstaller/vendor | electron-winstaller/vendor/7z-arm64.exe<br>electron-winstaller/vendor/7z.exe |
| `a36f5e81ce208137acc8fa9c00547c02…` | 448 KB | @electron/windows-sign | @electron/windows-sign/vendor/signtool.exe |
| `c7245e21a7553d9e52d434002a401c77…` | 436 KB | electron-winstaller/vendor | electron-winstaller/vendor/7z-x64.exe |
| `2edb4170c88c87547b8fb9bbce09e1ea…` | 344 KB | electron-winstaller/vendor | electron-winstaller/vendor/WixNetFxExtension.dll |
| `92a0afe94ccebcd877c3c7b05e80e8ad…` | 232 KB | electron-winstaller/vendor | electron-winstaller/vendor/signtool.exe |
| `ca420fef4909c10e2e95c8c899fa7d00…` | 172 KB | electron-winstaller/vendor | electron-winstaller/vendor/Microsoft.Deployment.WindowsInstaller.dll |
| `71d85bb2863f61ca11625e8bee171114…` | 44 KB | electron-winstaller/vendor | electron-winstaller/vendor/Microsoft.Deployment.Resources.dll |
| `6b441eb98b2771d6cb51de7d3e1b2eaf…` | 32 KB | electron-winstaller/vendor | electron-winstaller/vendor/light.exe |
| `310584b7170f81e7c21733628e5d46f2…` | 28 KB | electron-winstaller/vendor | electron-winstaller/vendor/candle.exe |

Pełne hashe (do wklejenia):
```
a36f5e81ce208137acc8fa9c00547c020fa10f044583002ccd23799b7f64078e
81f67048b7366870e5d49f00a8c570570c6a0dd11c05df7a09a8c52870cc83bd
31fd52f8996986623cf52c3b4d0f7ac74a9dec63fc16c902cef673eed550c435
b0cfdeaf429f5cc53f85123dd8f5a5feb92c19d31aa34df257edf9a26be05f95
c167dbedd388718c70c921eeeac825492733f76107190dc1ba17801c79da879e
65d0dcc70753ff3efd4631ac784d35ea5c22df7bd6fe2265a04382a7043d1512
9ed007aa82e440ceb39a6e105bb1d602a9bc59a4946267ba8de2f220aa15bc06
c7245e21a7553d9e52d434002a401c77a7ca7d0f245f2311b0ddf16f8f946c6f
310584b7170f81e7c21733628e5d46f28f6a9b900f94368f1b943d6e4bbd3253
6b441eb98b2771d6cb51de7d3e1b2eaf8c6cd045b4ef7bb1a26f297295d96100
71d85bb2863f61ca11625e8bee171114047d3f3e95792309e2040f3e139baae3
ca420fef4909c10e2e95c8c899fa7d009892dddf0b2424870236f1d0676e9165
61704f7dbe233980992f2a00ef9baacf64a8b157d688a4a4be6b7a2eaea02828
92a0afe94ccebcd877c3c7b05e80e8ad748f2c64959c431b88e7a7a1e5ce115f
4b3cf980a840f3e36d98fef3b4d4c302313ac7e2ea3310f5d0d71722853975c7
2edb4170c88c87547b8fb9bbce09e1ea202595331a06bedc3164326b3a84cdcb
```

## PRIORYTET 4 — świeżo zbudowane lokalnie (VT prawdopodobnie pusty)

| SHA-256 | Size | Package | Files |
|---|---|---|---|
| `cbe284ed7f2b27b190e881101f02ca97…` | 1.8 MB | better-sqlite3/build | better-sqlite3/build/Release/better_sqlite3.node |

Pełne hashe (do wklejenia):
```
cbe284ed7f2b27b190e881101f02ca9776dfc33de7b4262738bd6a32ebe7909f
```

## Czerwone flagi (na co uważać)

Gdy wkleisz hash i VT pokaże:
- ≥ 5 silników detekcji jako "Trojan", "Backdoor", "Stealer", "Miner" → STOP, nie buduj/nie uruchamiaj
- "Generic" / "Heuristic" detection od 1-2 silników na znanych narzędziach (signtool, Squirrel) → false positive zazwyczaj
- "First seen: <kilka dni temu>" na paczce którą rzekomo używasz od miesięcy → ALARM (możliwy supply chain)
- Brak rekordu na 7za.exe/Squirrel.exe → niespodziewane (te są na VT od lat) → sprawdź czy hash się zgadza z upstream release
