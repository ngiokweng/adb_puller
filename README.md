# adb-puller

直接把 Android 應用程式私有目錄中的檔案拉到電腦。手機需要 root，工具透過 `su` 讀取來源，再經 ADB 二進位串流傳送，不需要先搬到 `/sdcard`，也不會移動或刪除來源檔案。

## 解決的問題

1. 一般 `adb pull` 無法讀取應用程式私有檔案：使用 `adb exec-out` 執行 `su -c 'cat …'`，直接把檔案內容寫到本機。
2. 大檔案經中轉目錄後不完整：省去中轉步驟；以固定 4 MiB 緩衝區處理，支援超過 4 GiB 的大小，核對位元組數與 SHA-256，驗證成功後才發布目的檔案。

約 4 GiB 截斷的一個可能原因是 FAT32 單檔上限（4 GiB − 1 byte）；空間不足、I/O 錯誤或來源仍在寫入也可能造成問題。不能只依大小判定原因。這個工具避免手機中轉儲存的限制，但**電腦的目的磁碟仍須有足夠空間，並支援該檔案大小**，例如使用 NTFS、exFAT、APFS 或 ext4。

## 環境

- Python 3.10 以上；無第三方 Python 執行期依賴。
- Android SDK Platform-Tools 的 `adb`，已開啟並授權 USB 偵錯。
- 手機可透過 `su -c` 取得 root，並具有 `stat`、`sha256sum`、`cat`（現代 Android 通常已內建）。首次使用時需在手機允許 ADB shell 的 root 請求。
- 支援 Windows、macOS、Linux。macOS/Linux 的預設不覆寫發布方式使用硬連結，目的檔案系統須支援硬連結；exFAT 等檔案系統可使用 `--overwrite`。

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

`-s` 與 `--adb` 放在 `pull` / `devices` 子指令之前。當前版本一次拉取一個一般檔案；不支援整個目錄，也不會自動強制停止應用程式。

## 完整性與失敗處理

傳輸流程為：

1. 取得來源大小、檔案身分、時間與 SHA-256，確認雜湊計算期間來源資訊穩定。
2. 串流寫入目的目錄中的隨機 `.part` 暫存檔，同時計算接收內容的 SHA-256。
3. 核對收到的位元組數與雜湊，刷新本機檔案，再次檢查手機來源資訊與 SHA-256。
4. 全部一致後，才將暫存檔發布至指定檔名。預設拒絕覆寫；`--overwrite` 也只在驗證成功後取代舊檔。

SHA-256 前後檢查會在手機額外讀取來源兩次，20 GB 檔案可能需要明顯的等待時間；雜湊階段沒有固定逾時。傳輸階段會顯示進度與速度。來源若持續變動，請先停止對該檔案的寫入；資料庫與其 WAL 等多檔案的一致性仍需由應用程式的備份機制或停止應用程式保證。

斷線、空間不足、大小或雜湊不符、來源變動、`Ctrl+C` 等可處理的失敗會清除暫存檔並回報錯誤，不發布此次結果。系統斷電或程序被強制終止時，可能留下隨機命名的 `.part` 檔案，可自行刪除。目前不支援續傳。

## 測試

```powershell
python -m unittest discover -s tests -v
```

預設測試不連接手機。若要用已授權的 root 手機測試，以下命令會在 `/data/local/tmp` 建立唯一命名、僅 root 可讀的測試檔，完成後清除：

```powershell
$env:ADB_PULLER_DEVICE_TESTS = "1"
python -m unittest tests.test_device.DeviceTests.test_root_only_binary -v
```

超過 4 GiB 的實際傳輸測試另須明確開啟。電腦暫存磁碟需要約 4 GiB 可用空間；手機需支援 `truncate` 與稀疏檔案，測試來源只佔少量實體空間。可用 `ANDROID_SERIAL` 選裝置，或用 `ADB` 指定執行檔。

```powershell
$env:ADB_PULLER_DEVICE_TESTS = "1"
$env:ADB_PULLER_LARGE_TEST = "1"
python -m unittest tests.test_device.DeviceTests.test_over_four_gib -v
```

已在 Windows、Python 3.12 與具 root 權限的 Pixel 6 上驗證：24 項一般測試、套件安裝與命令列入口、root 私有權限目錄內含特殊字元檔名的二進位檔案，以及 4,294,967,297 bytes（4 GiB + 1 byte）的完整傳輸。大檔案測試同時核對 SHA-256 與 4 GiB 邊界後的位元組；測試用檔案會在完成後清除。
