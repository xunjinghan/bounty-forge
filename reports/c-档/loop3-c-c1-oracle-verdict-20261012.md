# Loop 3 路 C 妗ｈˉ鍏咃細C1 鍒ゅ畾 oracle 鐨勬渶缁堝畾璁猴紙鏃ュ織绾ч敋鐐癸級

- **浠诲姟**锛歵7 琛ラ仐锛堥槦闀块€氭姤銆宒eleteMe 鏄棤宸埆鍥炲寘銆嶅悗杩藉姞锛?- **鎵ц**锛歨unter-web锛沘ttempt_id `0d061d06-b986-48c7-ae2c-988180a5f29a`
- **鏃堕棿**锛?026-10-12 23:48 鈥?23:56锛圓sia/Shanghai锛?- **缁撹鍏堣**锛欳1 **鏃╁凡鐢ㄥ甯︼紙OOB锛夋墦閫氬苟瀹氭€?*锛涢槦闀跨殑銆宍deleteMe` 鏃犳晥銆嶅垽鏂?*鎴戝悓鎰?*锛屼絾闃熼暱闅忓悗鎻愬嚭鐨?*鏂?oracle锛坄BadPaddingException`锛夊悓鏍蜂笉瓒充互瀹氭€?*鈥斺€旂湡姝ｇ殑纭敋鐐瑰湪**鏃ュ織閲岀殑 `convertBytesToPrincipals` 琛屽彿**銆?
---

## 1. 鍥涗釜鍊欓€?oracle 鐨勫疄娴嬪鐓?
| # | 鍊欓€?oracle | 閿欒瀵嗛挜瀵嗘枃 | 姝ｇ‘瀵嗛挜 + 鍚堟硶娴?| 姝ｇ‘瀵嗛挜 + gadget | 鍒ゅ畾 |
|---|---|---|---|---|---|
| 1 | HTTP `Set-Cookie: rememberMe=deleteMe` | `true` | `true` | `true` | 鉂?**鏃犲尯鍒嗗害** |
| 2 | HTTP 鍝嶅簲鏃堕棿锛坄sleep N` 璁℃椂锛?| ~0.01s | ~0.01s | ~0.01s | 鉂?**鏃犲尯鍒嗗害**锛坄Runtime.exec` 寮傛锛?|
| 3 | 鏃ュ織 `BadPaddingException`锛堥槦闀挎彁妗堬級 | 鉁?鏈夛紙5 娆★級 | 鉂?**鏃?* | 鉂?**鏃?* | 鈿狅笍 **鍙兘鍒?瑙ｅ瘑澶辫触"锛屼笉鑳藉垽"鎴愬姛"** |
| 4 | **鏃ュ織 `convertBytesToPrincipals` 琛屽彿** | `AbstractRememberMeManager.java:429` | **`:431`** | **`:431`** | 鉁?**鍙弻鍚戝尯鍒?* |

### 1.1 涓轰粈涔?#3锛堥槦闀跨殑鎻愭锛変笉澶?
`BadPaddingException` 鏄?*鍗曡竟**鍒ゆ嵁锛氬畠鍦?*瑙ｅ瘑澶辫触**鏃跺嚭鐜帮紝浣?*瑙ｅ瘑鎴愬姛鏃朵笉鍑虹幇**鈥斺€旇€?涓嶅嚭鐜?涔熷彲鑳芥剰鍛崇潃"璇锋眰鏍规湰娌¤蛋鍒伴偅涓€姝?銆傛墍浠ワ細

- 鐢ㄥ畠鍒?澶辫触"鉁?鍙敤锛?- 鐢ㄥ畠鍒?鎴愬姛"鉂?**涓嶆垚绔?*锛堟棤寮傚父 鈮?鎴愬姛锛夈€?
**杩欐伆濂芥槸鎴戜笂涓€杞俯鐨勫悓涓€涓潙鐨勯暅鍍?*锛氭垜鎶?鏈?`deleteMe`"褰撳け璐ャ€侀槦闀挎妸"鏃?`BadPaddingException`"褰撴垚鍔熲€斺€斾袱鑰呴兘鏄嬁"缂哄け鐨勪俊鍙?鍘绘帹鏂?姝ｉ潰浜嬪疄"銆?
### 1.2 #4 鎵嶆槸纭敋鐐癸細琛屽彿涓嶅悓锛屾柟鍚戞槑纭?
Shiro 1.2.4 `AbstractRememberMeManager.convertBytesToPrincipals()` 鐨勪袱鏉″垎鏀?*琛屽彿涓嶅悓**锛?
```
澶辫触鍒嗘敮锛堣В瀵嗘姏寮傚父锛?
  Caused by: javax.crypto.BadPaddingException: Given final block not properly padded
    at ...AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:429)

鎴愬姛鍒嗘敮锛堣В瀵?OK銆佸弽搴忓垪鍖栦骇鍑哄璞°€佷粎绫诲瀷涓嶇锛?
  java.lang.ClassCastException: java.util.HashSet cannot be cast to org.apache.shiro.subject.PrincipalCollection
    at ...AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514)
    at ...AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431)
```

### 1.2.1 鈿狅笍 閿氱偣琛ㄨ堪绮剧‘鍖栵紙2026-10-13 00:05 淇锛岄噰绾抽槦闀垮鏍告剰瑙侊級

**淇鍓嶆垜鍐欑殑鏄?*锛氥€宍:431` 杩欎竴琛屽彧鑳借'瑙ｅ瘑鎴愬姛 + `readObject()` 鎴愬姛浜у嚭浜嗗璞?瑙﹁揪銆嶃€?**杩欏彞璇濅笉鍑嗙‘** 鈥斺€?缁忛槦闀挎寚鍑哄悗鎴戦€愬潡澶嶆牳鏃ュ織锛?*纭闃熼暱鏄鐨?*锛歚:431` 琚?*涓ょ被**寮傚父瑙﹁揪锛屽繀椤绘敹绱ц〃杩般€?
**淇鍚庣殑鍑嗙‘妯″瀷**锛坄AbstractRememberMeManager.convertBytesToPrincipals`锛夛細

| 琛屽彿 | 鍚箟 | 鏂█寮哄害 |
|---|---|---|
| `:429` | **瑙ｅ瘑闃舵**鎶涘紓甯革紙`CryptoException` 鈫?`BadPaddingException`锛?| 蹇呯劧澶辫触 |
| `:431` | **瑙ｅ瘑鎴愬姛銆佸凡杩涘叆鍙嶅簭鍒楀寲闃舵**锛坄deserialize()` 琚皟鐢級 | 鈿狅笍 **鍙瘉鏄?瑙ｅ瘑鎴愬姛"锛屼笉璇佹槑"鍙嶅簭鍒楀寲鎴愬姛"** |
| `:431` + `ClassCastException: HashSet cannot be cast` | 鍙嶅簭鍒楀寲**鐪熺殑浜у嚭浜嗗璞?*锛屼粎绫诲瀷涓嶇 | 鉁?**鐪熸垚鍔熼敋鐐?* |
| `:431` + `SerializationException: Unable to deserialze argument byte array.` | 瑙ｅ瘑鎴愬姛浣?*鍙嶅簭鍒楀寲澶辫触** | 鉂?澶辫触 |

**瀹屾暣鍙拌处锛堥€愬潡鍒囧垎锛岄潪鎶芥牱锛沗loop3-t7-c1-log-inventory-20261012.json`锛?*锛?
| 绫诲埆 | 璁℃暟 | 鏃堕棿鎴筹紙UTC锛?|
|---|---|---|
| A `:429` 瑙ｅ瘑澶辫触锛坄CryptoException`/`BadPaddingException`锛?| **5** | 15:09:33.057 / 15:18:39.291 / 15:19:00.964 / 15:33:54.922 / 15:33:56.591 |
| B `:431` 鍙嶅簭鍒楀寲澶辫触锛坄SerializationException`锛?| **2** | 15:18:40.540 / 15:19:02.185 |
| C **`:431` 鍙嶅簭鍒楀寲鎴愬姛锛坄ClassCastException: HashSet`锛?* | **1** | **15:38:29.985**锛? 鏈湴 23:38:29锛?|
| D 鍏跺畠 | 0 | 鈥?|

**琛岀骇鍘熷璁℃暟**锛堝鏁翠釜 461 琛屾棩蹇楋級锛歚BadPaddingException` 5 / `:429` 5 / `:431` **3** / `ClassCastException` 1 / `HashSet cannot be cast` 1 / `SerializationException` 2 / `ClassResolvingObjectInputStream` 2 / `EOFException` 2 鈥斺€?**涓庨槦闀跨嫭绔嬪绠楃殑璁℃暟瀹屽叏涓€鑷?*銆?
**涓轰粈涔堝繀椤绘敹绱?*锛氳嫢鏀句换"鐪嬪埌 `:431` 灏辨槸鎴愬姛"鐨勫啓娉曪紝涓嬩竴杞細鏈変汉琚?B 绫伙紙2 娆″弽搴忓垪鍖栧け璐ワ級璇 鈥斺€?閭ｅ皢鏄?*鏈疆绗笁娆″悓鏋勯敊璇?*锛堟嬁"杩涘叆闃舵"褰?鎴愬姛浜у嚭"锛夈€?*鐪熸鍙敤鐨勬垚鍔熼敋鐐瑰繀椤诲悓鏃舵弧瓒?`:431` 涓?`ClassCastException`銆?*

鏃ュ織涓?C 绫伙紙鐪熸垚鍔熼敋鐐癸級鐨勫師濮嬭褰曪紙甯︽椂闂存埑锛夛細

```
2026-10-12 15:38:29.985  WARN 1 --- [nio-8080-exec-4] o.a.shiro.mgt.DefaultSecurityManager : Delegate RememberMeManager instance of type [org.apache.shiro.web.mgt.CookieRememberMeManager] threw an exception during getRememberedPrincipals().

java.lang.ClassCastException: java.util.HashSet cannot be cast to org.apache.shiro.subject.PrincipalCollection
	at org.apache.shiro.mgt.AbstractRememberMeManager.deserialize(AbstractRememberMeManager.java:514) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.AbstractRememberMeManager.convertBytesToPrincipals(AbstractRememberMeManager.java:431) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.AbstractRememberMeManager.getRememberedPrincipals(AbstractRememberMeManager.java:396) ~[shiro-core-1.2.4.jar!/:1.2.4]
	at org.apache.shiro.mgt.DefaultSecurityManager.getRememberedIdentity(DefaultSecurityManager.java:604) [shiro-core-1.2.4.jar!/:1.2.4]
```

> `15:38:29.985` UTC = **鏈湴 23:38:29**锛岃惤鍦ㄦ垜鏈疆 C1 鍙栬瘉绐楀彛鍐咃紙23:30鈥?3:40锛夈€?> `java.util.HashSet` 姝ｆ槸 ysoserial `CommonsCollections6` 閾剧殑**椤跺眰鍙嶅簭鍒楀寲瀵硅薄**鈥斺€斾笌鎴戠殑 payload 缁撴瀯瀹屽叏瀵瑰簲銆?
**鏃ュ織閿氱偣璁℃暟**锛坄t7-shiro-full-dockerlogs.txt`锛?61 琛岋紱鍙拌处瑙?`loop3-t7-c1-log-inventory-20261012.json`锛夛細

| 閿氱偣 | 琛岀骇璁℃暟 | 寮傚父鍧楄鏁?| 鍒ゅ畾 |
|---|---|---|---|
| `:429` 瑙ｅ瘑澶辫触锛坄BadPaddingException`/`CryptoException`锛?| 5 | **5** | 蹇呯劧澶辫触 |
| `:431` 杩涘叆鍙嶅簭鍒楀寲闃舵 | 3 | 3 | 鈿狅笍 浠呰瘉鏄庤В瀵嗘垚鍔?|
| 鈫?鍏朵腑 `SerializationException`锛堝弽搴忓垪鍖栧け璐ワ級 | 2 | **2** | 鉂?澶辫触 |
| 鈫?鍏朵腑 `ClassCastException: HashSet cannot be cast`锛?*鐪熸垚鍔?*锛?| 1 | **1** | 鉁?**鎴愬姛閿氱偣** |
| `ClassResolvingObjectInputStream`锛圫hiro 鍙嶅簭鍒楀寲鍏ュ彛锛?| 2 | 鈥?| 璇佸疄 `readObject()` 琚皟鐢?|
| `EOFException`锛堢┖娴?鎴柇锛?| 2 | 鈥?| 鏃犲叧鏈缁撹 |

---

## 2. 鍥涗釜鐙珛鍒ゆ嵁鐨勪氦鍙夊嵃璇侊紙C1 鎴愬姛锛?
C1 鐨勫畾鎬?*涓嶄緷璧栦换浣曞崟鐐?oracle**锛岀敱鍥涘眰鐙珛璇佹嵁浜ゅ弶寰楀嚭锛?
| 鍒ゆ嵁 | 璇佹嵁 | 灞傜骇 |
|---|---|---|
| **J1 OOB 澶栧甫** | 鎺ユ敹绔敹鍒?`/t7badpad-cc6-0-root`銆乣/t7logoracle-cc6-0-root-3d7917aecbac`锛堝惈 `id -u`=0銆乣whoami`=root銆佸鍣ㄤ富鏈哄悕锛?| 搴旂敤灞?*鍛戒护鎵ц + 鍥炴樉** |
| **J2 瀹瑰櫒 `/proc`** | `FOUND_PROC pid=1279 cmd=[sleep 10 ]`锛?6 娆￠噰鏍峰懡涓級 | OS 灞?*瀛愯繘绋嬬湡鐨勮捣浜?* |
| **J3 鏃ュ織鎴愬姛閿氱偣** | `convertBytesToPrincipals(:431)` **涓?* `ClassCastException: java.util.HashSet`锛?5:38:29.985锛屽敮涓€ 1 娆★級 | 妗嗘灦灞?*瑙ｅ瘑+鍙嶅簭鍒楀寲鐪熺殑浜у嚭浜嗗璞?* |
| **J4 瀵嗛挜鑷瘉** | 鏈湴鐢ㄩ粯璁ゅ瘑閽ヨВ瀵嗚嚜宸辩殑 cookie 寰?`DECRYPT_OK` + magic `aced0005`锛?308B锛?| 瀵嗙爜瀛﹀眰 |

鍥涙潯鐙珛鍒ゆ嵁鎸囧悜鍚屼竴缁撹锛?*C1 瀹氭€т负鎴愬姛**銆?*涓嶄緷璧栦换浣曞崟杈?oracle銆?*

---

## 3. 鍏充簬"鏂版棩蹇楄鏁?= 0"鐨勭幇璞★紙濡傚疄璇存槑锛?
鎴戝湪鏈鍙楁帶瀹為獙閲岀敤銆宍docker logs` 琛屾暟澧為噺銆嶅垽瀹氶敋鐐癸紝寰楀埌 `new_log_lines: 0`銆傝繖涓嶆槸"娌″彂鐢?锛岃€屾槸锛?
- 鍏ㄩ噺鏃ュ織琛屾暟鍦ㄤ袱娆￠噰鏍烽棿涓?**443 鈫?443**锛岃€屾棭鍏堟姄鍙栫殑瀹屾暣蹇収鏄?**461 琛?* 鈫?璇存槑**鏃ュ織琚疆杞?鎴柇杩?*锛屼笉鑳界敤琛屽彿澧為噺鍋氶敋瀹氾紱
- 姝ｇ‘鍋氭硶鏄?*鎸夊唴瀹?+ 鏃堕棿鎴?*瀹氫綅锛埪?.2 宸茬粰鍑哄甫鏃堕棿鎴崇殑鍘熷琛岋級銆?
**杩欎釜鍧戞垜鐣欏湪鎶ュ憡閲?*锛歚docker logs` 琛屾暟澧為噺鍦ㄦ棩蹇楄疆杞満鏅笅涓嶅彲闈狅紝**閿氬畾鏃ュ織浜嬩欢瑕佸甫鏃堕棿鎴?*銆?
---

## 4. 闃熼暱鎸囧嚭鐨勪袱鐐癸紝鎴戦€愭潯鍥炲簲

### 4.1 銆宍deleteMe` 鏄棤宸埆鍥炲寘銆嶁€斺€?**鍚屾剰**

鎴戠殑鐙珛瀹炴祴涓庨槦闀夸竴鑷达細鍚堟硶搴忓垪鍖栨祦銆侀敊璇瘑閽ャ€佸瀮鍦炬槑鏂?*鍏ㄩ儴** `deleteMe=true`锛涙垜鍙﹀杩樻祴浜嗐€屼笉甯?cookie 鈫?`deleteMe=false`銆嶄笌銆宍rememberMe=` 绌哄€?鈫?`false`銆嶏紝鍙ˉ鍏呴槦闀跨殑琛ㄣ€?
**鎴戜笂涓€杞殑鑷垜绾犻敊涓庨槦闀跨粨璁虹浉鍚?*锛屼笖鎴戞妸閭ｄ唤琚帹缈荤殑璁℃椂娉曡瘉鎹紙`loop3-t7-c1-timing-20261012.json`锛変繚鐣欎簡锛屾湭鍒犳敼銆?
### 4.2 銆宍t7-c1-bruteforce-out.txt` 鐨?25 瀵嗛挜缁撹浣滃簾銆嶁€斺€?**鎺ュ彈锛屼笖鎴戝凡涓诲姩杩欐牱鏍囨敞**

璇ユ枃浠?*鏈鍒犳敼**锛宻ha256 浠嶄负 `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9`锛?169 瀛楄妭锛夈€?涓绘姤鍛?搂3 鐨?**N-C02** 宸插啓鏄庯細缁撹鏃犳晥銆乣EXECUTED_KEYS=[]` 涓嶅彲鐢ㄣ€?*鍚屾椂璇佹槑鏃犻渶鐖嗙牬锛堥粯璁ゅ瘑閽ュ嵆姝ｇ‘锛?*銆?*涓嶄富寮?鐖嗙牬鎴愬姛"**銆備笌闃熼暱鐨勫缃竴鑷淬€?
### 4.3 闃熼暱鎻愪緵鐨?`ensurePadding` 鎻愮ず 鈥斺€?**鏈夌敤锛屼絾鏈疆鏈Е鍙戣鍧?*

鎴戠殑 cookie 闀垮害锛?772 / 1792 / 1308 瀵嗘枃锛夊潎鍦?Base64 鍚庤嚜鍔ㄤ负 4 鐨勫€嶆暟锛宍ensurePadding` 鏈敼鍙樺瓧鑺傘€傚疄娴嬫垜鐨?cookie 鑳借 Shiro 鑷繁鐨?`AesCipherService` 姝ｇ‘瑙ｅ瘑锛堥槦闀垮湪 Kali 渚х嫭绔嬮獙璇侊細`SHIRO_DECRYPT_OK pt_len=82 head=aced000573720011`锛涙垜鍦ㄦ湰鏈洪獙璇?`DECRYPT_OK len=1308 magic=aced0005`锛夈€?*涓ゅ鐙珛楠岃瘉涓€鑷淬€?*

---

## 5. 杩橀渶瑕佺殑鍔ㄤ綔锛圕1 宸?closure锛屾涓鸿褰曪級

| 椤?| 鐘舵€?|
|---|---|
| C1 瀹氭€?| 鉁?**鎴愬姛**锛圝1+J2+J3+J4 鍥涘垽鎹氦鍙夛級 |
| 鏄惁浠嶉渶 URLDNS 棰勬 | 猬?**涓嶉渶瑕?*銆俇RLDNS 鐨勪环鍊兼槸"鍦ㄦ棤鍥炴樉鏃跺厛璇侀摼璺€?锛涙湰杞?*宸茬洿鎺ユ嬁鍒?HTTP 澶栧甫鍛戒护杈撳嚭**锛岄妫€浼氳鍚庨獙璇佹嵁瑕嗙洊銆?*鑻ラ槦闀垮潥鎸佽 DNS 灞傝瘉鎹?*锛屽彲鎸夐渶琛ュ仛锛堟帴鏀剁浠嶉檺鏈湴锛?|
| 寰呭姙 | 鏃狅紙C1/C2/C3 鍧囧凡浜や粯锛涘鍣ㄦ寜闃熼暱鎸囦护淇濈暀锛?|

---

## 6. 璇佹嵁鏂囦欢锛堢粷瀵硅矾寰?+ sha256锛?
| 鏂囦欢 | 鍐呭 | sha256 |
|---|---|---|
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-shiro-full-dockerlogs.txt` | **shiro 瀹瑰櫒鍏ㄩ噺鏃ュ織蹇収**锛堝惈 `:431` 鎴愬姛閿氱偣涓?`:429` 澶辫触閿氱偣锛屽甫鏃堕棿鎴筹級 | `6b37c61c4d4fcfed6036d7ce63f0323adfc9bc0f7f9b8acb6c66abf2db5d116b` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-logoracle-20261012.json` | 鍙楁帶鏃ュ織 oracle 瀹為獙锛堜笁鏂瑰鐓?+ 鍒ゅ畾锛?| `2380fd6f63aa8d534db8001ddc0fbebc51af754667674583ed22b34f2814d783` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-log-inventory-20261012.json` | **鏃ュ織寮傚父鍧楀畬鏁村彴璐?*锛堥€愬潡鍒囧垎锛宍:429`/`:431` 鍥涚被鍒嗙被 + 鏃堕棿鎴筹紝鏀拺 搂1.2.1 绮剧‘鍖栵級 | `d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-log-inventory.py` | 鍙拌处鐢熸垚鑴氭湰锛堝彲澶嶈窇锛?| `59e5070eb5abacc74e1576c3edbd8987de3c7a85da5ca70e9f950b7e105eb6ab` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\loop3-t7-c1-badpadding-oracle-20261012.json` | 闃熼暱 `BadPaddingException` 鎻愭鐨勯獙璇佽褰?| `af7b6fec1e3ecaa43a8c94e396b6a1b53b6ec08c7983cf3ccfd1ea1d9f4bd789` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-logstamp.sh` | 鏃ュ織閿氱偣瀹氫綅鑴氭湰 | `4575a13f0c00d37b6e426c946ad44dd84a81474930a0bb07e1b7b729c38bca6e` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-log-oracle.sh` | 鏃ュ織閿氱偣鎻愬彇鑴氭湰 | `2a196e909a8762e74e96c82154db2e932934a8c95df10589da239d981f0e8a01` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-logoracle.py` | 鍙楁帶鏃ュ織 oracle 瀹為獙鑴氭湰锛堝彲澶嶈窇锛?| `cf2b1bd3d566f34f1f7a799816b280e3da73951a18f79bb2a8dd8c1c0aff5761` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-badpadding-oracle.py` | `BadPaddingException` 鎻愭楠岃瘉鑴氭湰锛堝彲澶嶈窇锛?| `9554769d6a0e8abfa11b3690c3a2024fbff9d16c97818599a6a967fb2717c5d5` |
| `C:\Users\Administrator\Documents\deepseek-harness\default-workspace\security\learning\_evidence\t7-c1-bruteforce-out.txt` | **鍘熷璁板綍锛屾湭鍒犳敼**锛圢-C02 鏍囨敞涓烘棤鏁堢粨璁猴級 | `e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9` |

### 涓婅〃 sha256 鐨勬牳绠楁柟寮?
鍏ㄩ儴鐢?`Get-FileHash -Algorithm SHA256` 閫愭枃浠跺疄娴嬶紙鍛戒护涓庤緭鍑鸿涓嬫柟锛夛紝**鏃犲崰浣嶅€?*锛?
```
6b37c61c4d4fcfed6036d7ce63f0323adfc9bc0f7f9b8acb6c66abf2db5d116b  56159  t7-shiro-full-dockerlogs.txt
d9999386486cd56f2ffbe6c1ec2170fd96ce1777760290fd093b388ccc578074   3500  loop3-t7-c1-log-inventory-20261012.json
59e5070eb5abacc74e1576c3edbd8987de3c7a85da5ca70e9f950b7e105eb6ab   5194  t7-c1-log-inventory.py
2380fd6f63aa8d534db8001ddc0fbebc51af754667674583ed22b34f2814d783   1708  loop3-t7-c1-logoracle-20261012.json
af7b6fec1e3ecaa43a8c94e396b6a1b53b6ec08c7983cf3ccfd1ea1d9f4bd789   1745  loop3-t7-c1-badpadding-oracle-20261012.json
4575a13f0c00d37b6e426c946ad44dd84a81474930a0bb07e1b7b729c38bca6e   1010  t7-c1-logstamp.sh
2a196e909a8762e74e96c82154db2e932934a8c95df10589da239d981f0e8a01   1159  t7-c1-log-oracle.sh
cf2b1bd3d566f34f1f7a799816b280e3da73951a18f79bb2a8dd8c1c0aff5761   5906  t7-c1-logoracle.py
9554769d6a0e8abfa11b3690c3a2024fbff9d16c97818599a6a967fb2717c5d5   5303  t7-c1-badpadding-oracle.py
e27d26961b48611be36987a57fd749e64aa058dc2dbfaace9e15051be9e596d9   2169  t7-c1-bruteforce-out.txt
```

---

## 7. 鍙傝€?
- CVE-2016-4437 Apache Shiro rememberMe 鍙嶅簭鍒楀寲
- Shiro 1.2.4 `AbstractRememberMeManager`锛坄convertBytesToPrincipals` 琛屽彿 429/431 鍒嗘敮宸紓锛?- 涓绘姤鍛婏細`security/learning/loop3-c-vulhub-report-t7-20261012.md`
- 杩涘害璐︾洰锛歚security/learning/progress.md` 搂13

