# adb-puller

直接把 Android 應用程式私有目錄中的檔案或整個資料夾拉到電腦。手機需要 root，工具透過 `su` 讀取來源，再經 ADB 二進位串流傳送，不需要先搬到 `/sdcard`，也不會移動或刪除來源檔案。

## 解決的問題

1. 一般 `adb pull` 無法讀取應用程式私有檔案：使用 `adb exec-out` 透過 `su` 讀取，以 `dd` 分段平行傳輸；單路時使用 `cat`。可在傳輸途中使用快速 gzip 壓縮，本機解壓後寫入原始內容。
2. 大檔案經中轉目錄後不完整：省去中轉步驟；每個資料區塊最多 4 MiB，搭配有上限的佇列控制記憶體用量，支援超過 4 GiB 的大小，核對位元組數與 SHA-256，驗證成功後才發布目的檔案。

約 4 GiB 截斷的一個可能原因是 FAT32 單檔上限（4 GiB − 1 byte）；空間不足、I/O 錯誤或來源仍在寫入也可能造成問題。不能只依大小判定原因。這個工具避免手機中轉儲存的限制，但**電腦的目的磁碟仍須有足夠空間，並支援該檔案大小**，例如使用 NTFS、exFAT、APFS 或 ext4。

## 下載執行檔

從此儲存庫的 [Releases](https://github.com/ngiokweng/adb_puller/releases) 頁面下載符合電腦平台的壓縮檔，解壓縮後即可在終端機使用，**不需要安裝 Python**：

| 平台 | Release 附件 | 解壓後的執行檔 |
| --- | --- | --- |
| Windows x64 | `adb_puller-windows-x86_64.zip` | `adb_puller.exe` |
| Linux x64（Ubuntu 22.04 或更新的相容系統） | `adb_puller-linux-x86_64.tar.gz` | `adb_puller` |
| macOS Intel | `adb_puller-macos-x86_64.tar.gz` | `adb_puller` |
| macOS Apple Silicon | `adb_puller-macos-arm64.tar.gz` | `adb_puller` |

Windows PowerShell：

```powershell
.\adb_puller.exe devices
.\adb_puller.exe pull /data/user/0/com.example.app/files ./backup
.\adb_puller.exe --adb "C:\Android\platform-tools\adb.exe" devices
```

macOS / Linux：

```sh
./adb_puller devices
./adb_puller pull /data/user/0/com.example.app/files ./backup
```

執行檔已內含 Python，`adb` 仍需另外安裝 [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)，加入 `PATH` 或透過 `--adb` 指定路徑。手機仍需 root 與 USB 偵錯授權。Release 的 `SHA256SUMS` 可用來核對下載的壓縮檔。

## 環境

- 從原始碼執行時需要 Python 3.10 以上；無第三方 Python 執行期依賴。Release 執行檔不需要另裝 Python。
- Android SDK Platform-Tools 的 `adb`，已開啟並授權 USB 偵錯。
- 手機可透過 `su -c` 取得 root，並具有 `stat`、`sha256sum`、`cat`（現代 Android 通常已內建）。首次使用時需在手機允許 ADB shell 的 root 請求。
- 拉取資料夾時，手機另需內建的 `find`（支援 `-exec … {} +`）、`tar`、`tee`、`mkfifo` 與 `mktemp`。
- 加速功能使用手機內建的 `dd` 與 `gzip`。缺少 `dd` 時自動改為單路；自動模式缺少 `gzip` 時不壓縮，不會在手機建立中轉檔。
- 支援 Windows、macOS、Linux。macOS/Linux 單檔的預設不覆寫發布方式使用硬連結，目的檔案系統須支援硬連結；exFAT 等檔案系統可使用 `--overwrite`。資料夾整批下載不需要本機硬連結支援。

## 使用

在專案目錄直接執行：

```powershell
python -m adb_puller devices
python -m adb_puller pull /data/user/0/com.example.app/files/large.bin ./large.bin
```

本機路徑省略時儲存至目前目錄；若指定已存在的目錄，則保留來源檔名。含空白的路徑請用引號包住：

```powershell
python -m adb_puller pull "/data/user/0/com.example.app/files/my data.bin" "D:\Backups\my data.bin"
```

多台裝置、自訂 adb 路徑，以及覆寫現有檔案：

```powershell
python -m adb_puller -s DEVICE_SERIAL pull /data/user/0/com.example.app/files/large.bin ./large.bin
python -m adb_puller --adb "C:\Android\platform-tools\adb.exe" devices
python -m adb_puller pull /data/user/0/com.example.app/files/large.bin ./large.bin --overwrite
```

也可安裝命令列入口：

```powershell
python -m pip install -e .
adb-puller devices
adb-puller pull /data/user/0/com.example.app/files/large.bin ./large.bin
```

`-s` 與 `--adb` 放在 `pull` / `devices` 子指令之前。工具不會自動強制停止應用程式。

### 拉取整個資料夾

`pull` 自動辨識檔案或資料夾，不需要額外的遞迴旗標。資料夾會遞迴包含子目錄、隱藏檔與空目錄。整個目錄透過一條 tar 串流傳輸，預設在手機同步使用 `gzip -1` 壓縮；本機邊接收邊解壓至暫存目錄，最後核對整條打包串流的 SHA-256，成功後才發布內容。檔案數量增加時，不會為每個檔案額外啟動 ADB 或重複掃描來源計算雜湊。

```powershell
python -m adb_puller pull /data/user/0/com.example.app/files
python -m adb_puller pull /data/user/0/com.example.app/files "D:\Backups"
python -m adb_puller pull /data/user/0/com.example.app/files "D:\Backups" --overwrite
```

省略本機路徑時，建立 `./files/`。若 `D:\Backups` 已存在，目的地為 `D:\Backups\files\`；若指定尚不存在的路徑，該路徑就是目的資料夾。來源結尾的 `/` 不影響此規則。目的資料夾已存在時，預設拒絕下載；`--overwrite` 會在整批驗證成功後合併內容，取代同名檔案並保留本機其他檔案。

資料夾的 `--compression auto` 在手機有 gzip 時啟用壓縮，缺少時傳送未壓縮 tar；`--compression gzip` 要求 gzip 可用，`--compression none` 關閉壓縮。`--jobs` 僅用於單檔的分段傳輸，資料夾使用一條連續串流。傳輸進度顯示實際收到的打包串流位元組數與速度，完成後顯示解壓後的總大小與檔案數。

手機只在 `/data/local/tmp` 建立少量 FIFO、雜湊與狀態資訊，不儲存完整壓縮檔；結束後清除。本機只需容納解壓後的暫存內容；覆寫既有目錄時，原有資料與暫存內容會同時佔用空間。

目錄內的符號連結、裝置檔、socket 等特殊檔案會回報錯誤；不跟隨連結。檔名若無法安全對應至本機檔案系統（例如 Windows 的保留名稱或僅大小寫不同的重複檔名），也會在傳輸前回報錯誤。

傳輸、解壓或整批驗證失敗，以及發布前取消時，會清除整個暫存目錄，保留本機原有檔案。新目的目錄在驗證後整體重新命名；合併既有目錄時仍會依序發布檔案，若發布途中遇到本機 I/O 錯誤，可能已更新部分通過驗證的檔案。

整批 SHA-256 驗證保證收到的打包內容與手機送出的內容一致，並會檢查 tar 內容是否符合最初的目錄清單；不會對每個來源檔案做傳輸前後的雜湊比對。備份持續變動中的應用程式資料前，仍需停止寫入，確保多檔案的一致性。

## 傳輸速度

單檔預設等同於 `--jobs 4 --compression auto`。工具依來源大小使用最多 4 路 ADB 串流，各自讀取不同區段，在本機依偏移位置組合；小檔案會自動減少路數。自動壓縮會讀取開頭最多 256 KiB 作為樣本，若快速 gzip 預估可節省超過 10% 的資料量，就使用 `gzip -1` 串流壓縮。單檔進度與 MiB/s 以解壓後的原始大小計算。

可調整並行數（1–8）或強制開關壓縮：

```powershell
python -m adb_puller pull /data/user/0/com.example.app/files/large.log ./large.log --jobs 4 --compression gzip
python -m adb_puller pull /data/user/0/com.example.app/files/archive.zip ./archive.zip --compression none
python -m adb_puller pull /data/user/0/com.example.app/files/large.bin ./large.bin --jobs 1 --compression none
```

Log、文字與大量重複內容通常適合壓縮；ZIP、影片等資料通常維持未壓縮。若開頭樣本與其餘內容差異很大，可手動指定模式。實際速度仍取決於 USB 連線、手機 CPU、儲存裝置及其他同時使用 ADB 的程式。已開始的 pull 不會套用新設定，下一次執行才會使用加速路徑。

資料夾整批傳輸在 Windows、Python 3.12、Pixel 6 上，以同一批 25 個小型 log（共 188,800 bytes），使用預設設定比較完整下載時間；兩份結果均逐檔核對測試內容：

| 目錄傳輸方式 | 完整時間 | root ADB 呼叫次數 |
| --- | ---: | ---: |
| 舊版逐檔下載與驗證 | 25.89 秒 | 227 |
| tar/gzip 串流與整批 SHA-256 | 1.42 秒 | 3 |

這組小檔樣本約快 18.3 倍。三次呼叫分別用於辨識來源、列出目錄與傳輸整批內容，數量不隨檔案數增加；實際加速幅度依檔案大小、壓縮率與裝置而異。

同一台裝置的 1,000 個 log（共 7,552,000 bytes）整批下載為 19.90 秒，同樣只呼叫 root ADB 三次，全部內容均核對一致。

第一輪傳輸加速於 Windows、Pixel 6、USB 2.0 High-Speed 下，以同一份 128 MiB log 樣本進行完整 pull 實測（當時來源雜湊仍在傳輸前完成，另有一筆 pull 同時執行）：

| 設定 | 傳輸階段速度 | 含前後 SHA-256、寫檔與驗證的總時間 |
| --- | ---: | ---: |
| `--jobs 1 --compression none` | 7.65 MiB/s | 17.98 秒 |
| `--jobs 4 --compression none` | 17.05 MiB/s | 8.79 秒 |
| `--jobs 4 --compression auto` | 41.28 MiB/s | 4.24 秒 |

三次結果的 SHA-256 一致；這組 log 的傳輸速度約提高 5.4 倍，完整流程約快 4.2 倍。此數值代表可壓縮樣本的解壓後吞吐量，其他檔案的結果會不同。

## 完整性與失敗處理

單檔傳輸流程為（資料夾使用上述整批打包流程）：

1. 取得來源大小、檔案身分與時間，啟動背景 SHA-256 計算，隨即開始傳輸。
2. 串流寫入目的目錄中的隨機 `.part` 暫存檔；多路傳輸依區段偏移寫入，gzip 在本機以有上限的區塊解壓。同時在手機計算初始來源 SHA-256，完成後核對來源資訊是否穩定。
3. 核對收到的位元組數，按檔案順序讀取組合後的本機檔案，與初始來源 SHA-256 比對，刷新本機檔案，再次檢查手機來源資訊與 SHA-256。
4. 全部一致後，才將暫存檔發布至指定檔名。預設拒絕覆寫；`--overwrite` 也只在驗證成功後取代舊檔。

SHA-256 前後檢查仍會在手機額外讀取來源兩次；第一次與傳輸重疊執行，因此開始 pull 時不必先等整個檔案掃描完。若傳輸先完成，工具會在「核對來源 SHA-256」階段等待剩餘計算，驗證成功後才發布檔案。背景雜湊失敗會中止傳輸，取消或其他失敗也會終止並回收雜湊子程序。雜湊沒有固定逾時，大檔案的最終來源複查仍需時間。

同一台 Pixel 6 的 4 GiB + 1 byte 稀疏測試檔實測：初始來源資訊階段由 5.27 秒降至 0.11 秒，首次收到資料由 6.26 秒提前至 1.08 秒，完整流程由 19.29 秒降至 14.36 秒。兩次結果 SHA-256 一致；這組數值用來比較雜湊排程，大量零資料的傳輸時間不代表一般 log 或二進位檔案。

傳輸階段會顯示進度與速度。來源若持續變動，請先停止對該檔案的寫入；資料庫與其 WAL 等多檔案的一致性仍需由應用程式的備份機制或停止應用程式保證。

斷線、空間不足、大小或雜湊不符、來源變動、`Ctrl+C` 等可處理的失敗會清除暫存檔並回報錯誤，不發布此次結果。系統斷電或程序被強制終止時，可能留下隨機命名的 `.part` 檔案，可自行刪除。目前不支援續傳。

## 發布 Release

[Release workflow](.github/workflows/release.yml) 會在推送任意新 tag 時，自動於 Windows、Linux、macOS Intel 與 Apple Silicon 上執行測試，再以 PyInstaller 打包。壓縮檔解壓後的執行檔也會在專案目錄之外測試 `--help` 與 `pull --help`，確認可獨立啟動。

先將 workflow 與程式碼提交並推送至 GitHub，再建立指向該提交的 tag：

```sh
git tag v0.1.0
git push origin v0.1.0
```

四個平台全部成功後，workflow 透過 GitHub CLI 建立對應 tag 的 Release、上傳四份壓縮檔與 `SHA256SUMS`，並自動產生版本說明。附件上傳完成後才發布 Release；重跑同一個 tag 的 workflow 會更新同名附件。使用內建的 `GITHUB_TOKEN`，不需要另外設定個人 token。

可用 GitHub CLI 查看進度與下載附件：

```sh
gh run list --workflow release.yml
gh release view v0.1.0
gh release download v0.1.0 --pattern 'adb_puller-windows-x86_64.zip'
```

在 Actions 頁面手動執行 **Release** workflow，只會測試、打包並保留建置產物，不會發布 Release。

若要在本機打包，使用 Python 3.12 執行：

```sh
python -m pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean --onefile --name adb_puller --paths . --specpath build adb_puller/__main__.py
```

執行檔位於 `dist/`，對應目前電腦的作業系統與架構；跨平台版本由 GitHub Actions 分別建置。

## 測試

```powershell
python -m unittest discover -s tests -v
```

預設測試不連接手機。若要用已授權的 root 手機測試，以下命令會在 `/data/local/tmp` 建立唯一命名、僅 root 可讀的測試檔，完成後清除：

```powershell
$env:ADB_PULLER_DEVICE_TESTS = "1"
python -m unittest tests.test_device.DeviceTests.test_root_only_binary -v
python -m unittest tests.test_device.DeviceTests.test_root_only_directory -v
```

超過 4 GiB 的實際傳輸測試另須明確開啟。電腦暫存磁碟需要約 4 GiB 可用空間；手機需支援 `truncate` 與稀疏檔案，測試來源只佔少量實體空間。可用 `ANDROID_SERIAL` 選裝置，或用 `ADB` 指定執行檔。

```powershell
$env:ADB_PULLER_DEVICE_TESTS = "1"
$env:ADB_PULLER_LARGE_TEST = "1"
python -m unittest tests.test_device.DeviceTests.test_over_four_gib -v
```

已在 Windows、Python 3.12 與具 root 權限的 Pixel 6 上驗證：60 項一般測試、root 私有權限目錄內含特殊字元檔名的二進位檔案、目錄的 auto/gzip/none 三種模式、符號連結拒絕處理，以及中途取消後的手機 FIFO 與本機暫存清理。一般測試涵蓋平行區段亂序組合、gzip 截斷與損毀、背景雜湊與傳輸重疊執行、目錄串流 SHA-256 與完成標記、解壓路徑與硬連結檢查、整批驗證後合併覆寫，以及失敗與取消時的清理。

先前亦已驗證 4,294,967,297 bytes（4 GiB + 1 byte）的完整傳輸，同時核對 SHA-256 與 4 GiB 邊界後的位元組。測試用檔案會在完成後清除。
