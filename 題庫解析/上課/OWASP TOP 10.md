# OWASP TOP 10
```
https://secbuzzer.co/post/116
https://secbuzzer.co/post/115

A1:2017-Injection　注入攻擊
A2:2017-Broken Authentication　無效的身分驗證
A3:2017-Sensitive Data Exposure　機敏資料外洩
A4:2017-XML External Entities (XXE) [NEW]　XML 外部處理器弱點
A5:2017-Broken Access Control [Merged]　無效的存取控管
A6: 2017-Security Misconfiguration　不安全的組態設定
A7:2017-Cross-Site Scripting (XSS)　 跨站腳本攻擊
A8:2017-Insecure Deserialization　不安全的反序列化弱點
A9:2017-Using Components with Known Vulnerabilities　使用已知弱點套件
A10:2017-Insufficient Logging & Monitoring　紀錄與監控不足風險
```
### A1:2017-Injection　注入攻擊
```
廣為人知的是 SQL Injection，通常會發生在惡意程式輸入時
因為沒有經過妥善的檢查、排除符號等

建議的控制措施為：
1.使用 Prepared Statements、Stored Procedures
2.嚴密檢查所有輸入值  input validation
3.控管錯誤訊息僅管理者可以閱讀
4.使用過濾字串函數過濾非法的字元
5.控管資料庫及網站使用者帳號權限
```
```
command Injection
```
```
SQL Injection
https://owasp.org/www-community/attacks/SQL_Injection
```

```
LDAP Injection
https://kknews.cc/zh-tw/news/yegpnnb.html
```
### A2:2017-Broken Authentication　無效的身分驗證
```
脆弱的帳戶認證，或採取了不安全的管理機制
容易造成帳號/身分盜用，或身分認證機制無效化
有心人士可肆意在伺服器做任何新增修改刪除查詢，進而接管主機

建議的控制措施為：
1.使用完善的 Cookie Session 保護機制
2.不允許外部 Session
3.登入及修改資訊頁面使用 SSL 加密
4.設定完善的 Timeout 機制
5.多因素認證
6.驗證密碼強度及密碼定期更換機制
```
### A3:2017-Sensitive Data Exposure　機敏資料外洩
```
資料未加密、或使用脆弱的金鑰
易使密碼被攻破，造成機敏資料外洩
常見於網路應用程式對於資料的保護不足
駭客取得即可偽造 / 竊取身分，或進行其他的犯罪行為

建議的控制措施為：
1.備份檔、開發版本不應出現於正式機上 
2.使用完善的 Cookie Session 保護機制。
3.軟體中已經被識別的機敏資料，於實作階段應考量於傳輸時、儲存時、備份後，採用加密作法。
4.使用國際機構驗證且未遭破解的演算法，不使用自行創造加密方式。
5.盡可能使用該演算法支援的最大金鑰長度。應對金鑰進行適當保護，金鑰應定期更換。
```
### A4:2017-XML External Entities (XXE) [NEW]　XML 外部處理器弱點
```
以 XML 為基礎的網路應用程式沒有做好管控權限，直接讀取外部資源提供的 XML 檔案
攻擊者可以利用 XML 為基礎，讓系統讀取後，進行文件的共享、監聽內部網路、執行遠端程式，導致資料外洩，或系統被駭客接管

建議的控制措施為：
1.修補或升級有引用的套件，並將 XML 升級到最新。
2.驗證 XML 或 XSL 文件是否經 SCD 驗證會類似方法傳入。
3.禁止外部實體引用。
```
### A5:2017-Broken Access Control [Merged]　無效的存取控管
```
攻擊者可透過網址或 HTML 頁面，繞過存取控制
或將自己的權限提升自管理者，進而攻破公司系統等

建議的控制措施為：
1.避免將物件直接暴露給使用者。
2.驗證所有物件是否為正確。
3.預設禁止任何存取行為，並先判斷使用者是否有權限。
```
### A6: 2017-Security Misconfiguration　不安全的組態設定
```
系統的安全性取決於應用程式、伺服器，及平台的設定
系統的設定也要與版本和漏洞配合，才能確保系統安全無虞

建議控制措施：
1.關閉不需要的帳號、頁面、服務、port。
2.不使用預設密碼。
3.確保軟體、作業系統已更新至最新版本。
```
### A7:2017-Cross-Site Scripting (XSS)跨站腳本攻擊
```
網站應用程式缺乏適當的驗證，直接將來自使用者的執行請求送回瀏覽器執行
攻擊者可擷取使用者的 Cookie 資訊，假冒身分成為合法使用者
甚至將使用者轉址至惡意網站或執行惡意腳本程式（Script）

跨站腳本攻擊（XSS）好發於網站上的搜尋欄、留言版、網址列
有自動化掃描工具能夠偵測網站是否存在 XSS 漏洞，幫助加快漏洞修補的速度

建議控制措施：
1.驗證輸入的資料。
2.將資料編碼後再進行輸出。
3.同時使用白名單與黑名單機制過濾資料。
```
### A8:2017-Insecure Deserialization　不安全的反序列化弱點
```
當攻擊者提供竄改後的惡意物件進行反序列化，可能導致應用程式或 API 出現不安全的風險
例如：注入攻擊（Injection）、跨站腳本攻擊（XSS）、遠端程式碼執行

建議控制措施：
1.不接受來自不信任來源的序列化物件。
2.只允許原始資料型態進行反序列化。
3.將序列化的物件加上數位簽章或進行加密，防止新增惡意物件或資料竄改。
4.記錄反序列化所發生的例外情況與失敗訊息。
5.監控反序列化，當用戶持續進行反序列化時，應啟動警告機制。
```
### A9:2017-Using Components with Known Vulnerabilities　使用已知弱點套件
```
系統使用的外部元件或函式庫尚未更新至最新的版本（Stable Release）
該元件或函式庫已具有弱點，攻擊者便可利用其弱點進行攻擊。

建議控制措施：
1.識別所有使用到的第三方元件及其版本。
2.定期檢視所使用元件的公開安全資訊，以確保接收到第三方元件的安全訊息。
3.建立安全政策，指導第三方元件的使用原則，例如：需要了解其安全性、通過安全性測試才得以使用。
```
### A10:2017-Insufficient Logging & Monitoring　紀錄與監控不足風險
```
系統未記錄或記錄不足夠的訊息
例如：未記錄來自應用程式與 API 的可疑活動，或遇到可疑活動時，未建立即時有效率的處理流程等

駭客能進一步攻擊系統非法竄改、存取或銷毀系統的資料，能達成目的且不被及時發現。

建議控制措施：
1.確保登錄、存取失敗、驗證失敗的訊息都能被完整記錄，並保留足夠的用戶資訊，以辨別可疑或惡意行為。
2.確保高額交易能有完整的審計訊息（audit trail），以防被竄改或刪除。
3.建立有效的監控與警告機制，使可疑活動在短時間內能夠被發現及應對。
```
