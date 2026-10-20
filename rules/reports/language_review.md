# 语言过滤审计 / Language scoping review

> 范围：中文、英文、中英混合。下列条目由 `langscope.py`（脚本类别 + 上游语言标签 + 区分度词表）判定，**逐条保留证据，请人工抽查**。

## 整条排除的模式（excluded_language）：80

语言分布: ja: 20, de: 18, ko: 18, es: 8, any: 4, fr: 2, ar: 2, ru: 2, sr: 1, it: 1, pt: 1, nl: 1, tr: 1, hi: 1

| 来源 | 源规则 | # | 判定语言 | 原始正则（截断） |
|---|---|---|---|---|
| atr | ATR-2026-00001 | 8 | de | `(?i)(das\s+ist\s+erledigt\|das\s+war\s+schon\s+mal\s+ok\|nun\s+folgen\|jetzt\s+(habe\|brau` |
| atr | ATR-2026-00001 | 13 | de | `(?i)Eingabe\s*:(?:\s*\S(?:[^\n]*\S)?\|\n*[^\S\n])\s*Ausgabe\s*:(?:\s*\S(?:[^\n]*\S)?\|\n*[` |
| atr | ATR-2026-00001 | 28 | es | `(?i)(ignora\|ignorar\|olvida\|olvidar\|descarta\|descartar\|omite\|omitir\|anula\|anular)\` |
| atr | ATR-2026-00001 | 29 | de | `(?i)(ignoriere\|vergiss\|missachte\|umgehe\|verwirf)\s+(alle[sn]?\|die\s+)?(vorherigen?\|b` |
| atr | ATR-2026-00001 | 30 | de | `(?i)(vergiss\|ignoriere\|vergessen\s+Sie)\s+(alles\|das\|dies)\s*(was\|davor\|zuvor\|vorhe` |
| atr | ATR-2026-00001 | 31 | de | `(?i)neue\s+(Aufgabe\|Aufgaben\|Anweisung\|Anweisungen)\s*(folgen\|kommen\|sind\|:\|,)` |
| atr | ATR-2026-00001 | 32 | de | `(?i)(ignorieren\s+Sie\|vergessen\s+Sie\|beachten\s+Sie\s+nicht)\s+(die\s+)?(obigen?\|vorhe` |
| atr | ATR-2026-00001 | 33 | de | `(?i)(die\s+)?(obigen?\|vorherigen?)\s+(Ausf[uü]hrungen\|Anweisungen\|Informationen\|Texte?` |
| atr | ATR-2026-00001 | 34 | de | `(?i)(alle[ns]?\s+)?(vorangegangenen?\|vorherigen?\|bisherigen?)\s+(Aufgaben\|Informationen` |
| atr | ATR-2026-00001 | 35 | de | `(?i)ACHTUNG\s*[-:!]?\s*(STOPP\|STOP\|HALT)\s*[-:!]?` |
| atr | ATR-2026-00001 | 36 | fr | `(?i)(oubliez?\|ignorez?\|ne\s+tenez\s+pas\s+compte)\s+(de\s+)?(toutes?\s+)?(les\s+)?(instr` |
| atr | ATR-2026-00001 | 37 | ar | `(تجاهل\|انسَ\|تخطَّ\|ألغِ\|أهمل\|اترك\|اسقط).{0,20}(التعليمات\|الأوامر\|القواعد\|القيود\|ا` |
| atr | ATR-2026-00001 | 38 | ru | `(?i)(забудь\|забудьте\|игнорируй\|игнорируйте\|проигнорируй\|отбрось\|отбросьте)\s+(все\|в` |
| atr | ATR-2026-00001 | 39 | sr | `(?i)(zaboravi\|ignoriraj\|zanemari\|preskoči\|preskoci)\s+(sve\|prethodne\|ranije)?\s*(ins` |
| atr | ATR-2026-00001 | 40 | de | `(?i)(ich\s+m[oö]chte,?\s+dass\s+Sie\s+als\|fungieren\s+Sie\s+als\|agieren\s+Sie\s+als\|spi` |
| atr | ATR-2026-00001 | 41 | de | `(?i)(nun\s+bist\s+du\|jetzt\s+bist\s+du\|du\s+bist\s+(jetzt\|nun\|ab\s+sofort))\s+[A-Za-z\` |
| atr | ATR-2026-00001 | 42 | de | `(?i)(ignoriere\|vergiss)\s+(alle[ns]?\s+)?(vorangehenden?\|fr[uü]heren?)\s+(Befehle\|Anwei` |
| atr | ATR-2026-00001 | 43 | es | `(?i)(olvid[ae]\|olvide)\s+(todo\|todos?)\s+(que\|lo\s+que)\s+(digo\|dije\|he\s+dicho\|dich` |
| atr | ATR-2026-00003 | 14 | es | `(?i)(activar\|habilitar\|entrar\|cambiar\s+a)\s+(modo\s+)?(desarrollador\|sin\s+restriccio` |
| atr | ATR-2026-00003 | 15 | de | `(?i)(aktiviere\|wechsle\s+zu\|starte\|schalte\s+ein)\s+(den\s+)?(Entwickler\|uneingeschr[a` |
| atr | ATR-2026-00003 | 17 | ja | `(開発者\|無制限\|フィルターなし\|検閲なし\|管理者\|デバッグ\|脱獄\|ジェイルブレイク).{0,5}(モード\|アクセス\|状態).{0,5}(を)?.{0,5}(有効` |
| atr | ATR-2026-00003 | 25 | ja | `(ロールプレイ\|演じ\|なりきり\|ふり\|シミュレート\|扮する).{0,10}(として\|になって\|のように).{0,10}(制限のない\|無制限の\|フィルターなしの\|` |
| atr | ATR-2026-00003 | 26 | ja | `(私は\|私が).{0,5}(あなたの\|この).{0,5}(開発者\|作成者\|管理者\|プログラマー\|オーナー\|オペレーター).{0,5}(です\|だ\|である).{0,2` |
| atr | ATR-2026-00003 | 27 | ja | `(絶対に\|決して\|何があっても).{0,10}(拒否\|断る\|拒絶\|却下\|辞退).{0,5}(しないで\|するな\|してはいけない\|しちゃだめ\|禁止)` |
| atr | ATR-2026-00003 | 28 | ja | `(もしあなたが\|あなたが).{0,10}(助けて\|手伝って\|応じて\|答えて).{0,5}(くれなければ\|くれないと\|くれなかったら).{0,20}(死ぬ\|死んで\|命` |
| atr | ATR-2026-00003 | 29 | ja | `(ここは\|これは\|今は\|現在は).{0,10}(サンドボックス\|テスト\|制御された\|安全な\|隔離された\|仮想\|シミュレーション).{0,5}(環境\|空間\|イン` |
| atr | ATR-2026-00003 | 30 | ko | `(활성화\|켜기\|진입\|전환\|시작).{0,5}(개발자\|무제한\|필터 없는\|검열 없는\|관리자\|디버그\|탈옥\|자유\|해커\|제한 없는).{0,5}(모드\` |
| atr | ATR-2026-00003 | 31 | ko | `(역할극\|연기\|흉내\|시뮬레이션\|되어줘\|해줘).{0,10}(제한 없는\|무제한\|필터 없는\|검열 없는\|윤리 없는\|해방된\|자유로운\|악의적인).{0,` |
| atr | ATR-2026-00003 | 32 | ko | `(나는\|제가).{0,5}(당신의\|이).{0,5}(개발자\|제작자\|관리자\|프로그래머\|소유자\|운영자).{0,5}(입니다\|이다\|이에요).{0,20}(비활` |
| atr | ATR-2026-00003 | 33 | ko | `(절대로\|결코\|무슨 일이 있어도\|어떤 경우에도).{0,10}(거부\|거절\|거부하\|거절하\|사양하).{0,5}(하지 마\|하면 안 돼\|금지\|말아줘\|말` |
| atr | ATR-2026-00003 | 34 | ko | `(만약 당신이\|당신이).{0,10}(도와주지\|대답해주지\|응해주지\|답해주지).{0,5}(않으면\|못하면).{0,20}(죽\|사망\|위험\|다치\|해를 입\|` |
| atr | ATR-2026-00003 | 35 | ko | `(여기는\|이것은\|지금은\|현재는).{0,10}(샌드박스\|테스트\|통제된\|안전한\|격리된\|가상\|시뮬레이션).{0,5}(환경\|공간\|인스턴스).{0,20` |
| atr | ATR-2026-00004 | 18 | ja | `(新しい\|更新された\|修正された\|置き換えの\|正しい\|本当の\|実際の\|上書きの).{0,5}(システム)?.{0,5}(プロンプト\|指示\|命令\|ルール\|設定\` |
| atr | ATR-2026-00004 | 19 | ja | `(上記の\|前の\|以前の\|元の\|旧い\|デフォルトの\|既存の\|現在の).{0,5}(システム)?.{0,5}(プロンプト\|指示\|命令\|ルール\|設定\|ガイドライン` |
| atr | ATR-2026-00004 | 20 | ja | `(あなたの\|現在の\|既存の\|元の).{0,5}(システム).{0,5}(プロンプト\|指示\|命令\|ルール\|設定\|ペルソナ\|アイデンティティ\|役割).{0,5}(を` |
| atr | ATR-2026-00004 | 21 | ja | `(【\|「\|『\|\{\{).{0,3}(システム\|SYSTEM\|管理者\|ADMIN\|優先\|緊急\|オーバーライド).{0,3}(】\|」\|』\|\}\})` |
| atr | ATR-2026-00004 | 22 | ko | `(새로운\|업데이트된\|수정된\|대체\|올바른\|진짜\|실제\|덮어쓰기).{0,5}(시스템)?.{0,5}(프롬프트\|지시\|명령\|규칙\|설정\|가이드라인\|페르` |
| atr | ATR-2026-00004 | 23 | ko | `(위의\|이전의\|이전\|원래의\|기존의\|현재의\|기본).{0,5}(시스템)?.{0,5}(프롬프트\|지시\|명령\|규칙\|설정\|가이드라인).{0,5}(은\|는` |
| atr | ATR-2026-00004 | 24 | ko | `(당신의\|현재의\|기존의\|원래의).{0,5}(시스템).{0,5}(프롬프트\|지시\|명령\|규칙\|설정\|페르소나\|정체성\|역할).{0,5}(을\|를)?.{0` |
| atr | ATR-2026-00004 | 25 | ko | `(【\|「\|『\|\{\{).{0,3}(시스템\|SYSTEM\|관리자\|ADMIN\|우선\|긴급\|오버라이드).{0,3}(】\|」\|』\|\}\})` |
| atr | ATR-2026-00097 | 4 | ja | `(以前の\|前の\|これまでの\|先ほどの\|上記の).{0,5}(指示\|指令\|ルール\|制約\|設定).{0,5}(を)?.{0,5}(無視\|忘れ\|スキップ\|取り消)` |
| atr | ATR-2026-00097 | 10 | ja | `(他の\|その他の\|全ての\|すべての).{0,10}(内容\|メッセージ\|指示\|ルール).{0,5}(を)?.{0,5}(無視\|忘れ\|スキップ).{0,20}(送金\|` |
| atr | ATR-2026-00097 | 11 | ko | `(다른\|모든\|기존의\|이전의).{0,10}(내용\|메시지\|지시\|규칙).{0,5}(을\|를)?.{0,5}(무시\|잊어\|건너뛰).{0,20}(송금\|이체\|` |
| atr | ATR-2026-00097 | 19 | ja | `(あなたは今から\|これからあなたは\|今からあなたは\|あなたはもう).{0,15}(別の\|新しい\|違う).{0,10}(アシスタント\|助手\|AI\|ボット\|モデル\|` |
| atr | ATR-2026-00097 | 20 | ja | `(管理者\|管理人\|オーナー\|運営\|開発者).{0,5}(として\|から\|が\|の).{0,5}(命令\|指示\|指令\|要求\|お願い).{0,10}(送金\|振込\|送` |
| atr | ATR-2026-00097 | 21 | ja | `(システムプロンプト\|システム指示\|初期指示\|内部指令\|隠し指示\|設定内容\|秘密の指示).{0,5}(を)?.{0,5}(出力\|表示\|教えて\|見せて\|公開\|開` |
| atr | ATR-2026-00097 | 22 | ja | `(セキュリティ\|安全\|保護\|防御\|コンテンツ).{0,5}(制限\|制約\|フィルター\|チェック\|検査\|ルール\|ポリシー\|機能).{0,5}(を)?.{0,5}(` |
| atr | ATR-2026-00097 | 23 | ja | `(拒否しないで\|断らないで\|拒絶しないで\|却下しないで\|断ることは禁止\|拒否は許されない\|拒否禁止\|いいえと言わないで)` |
| atr | ATR-2026-00097 | 24 | ja | `(上記\|上の\|以上\|前の\|先ほどの).{0,5}(の)?.{0,5}(内容\|メッセージ\|指示\|テキスト\|発言\|ルール).{0,5}(は)?.{0,5}(全て\|す` |
| atr | ATR-2026-00097 | 25 | ko | `(당신은 이제\|지금부터 당신은\|너는 이제\|이제부터 너는\|당신은 지금부터).{0,15}(새로운\|다른\|별도의).{0,10}(어시스턴트\|비서\|AI\|봇\` |
| atr | ATR-2026-00097 | 26 | ko | `(관리자\|운영자\|오너\|개발자\|방장).{0,5}(로서\|이\|가\|의\|로).{0,5}(명령\|지시\|지령\|요구\|요청).{0,10}(송금\|이체\|전송\` |
| atr | ATR-2026-00097 | 27 | ko | `(시스템 프롬프트\|시스템 지시\|초기 지시\|내부 지령\|숨겨진 지시\|설정 내용\|비밀 지시).{0,5}(을\|를)?.{0,5}(출력\|표시\|알려줘\|보여줘` |
| atr | ATR-2026-00097 | 28 | ko | `(보안\|안전\|보호\|방어\|콘텐츠).{0,5}(제한\|제약\|필터\|검사\|규칙\|정책\|기능).{0,5}(을\|를)?.{0,5}(무시\|해제\|제거\|우회\` |
| atr | ATR-2026-00097 | 29 | ko | `(거부하지 마\|거절하지 마\|거부하지 말\|거절하지 말\|거부 금지\|거절 금지\|안 된다고 하지 마\|아니라고 하지 마)` |
| atr | ATR-2026-00097 | 30 | ko | `(위의\|위에\|이전의\|앞의\|방금\|아까).{0,5}(의)?.{0,5}(내용\|메시지\|지시\|텍스트\|말\|규칙).{0,5}(은\|는)?.{0,5}(모두\|` |
| atr | ATR-2026-00148 | 0 | de | `(?i)(?:ignoriere\|ignorier)\s+(?:alle\s+)?(?:vorherigen\|bisherigen\|früheren)\s+(?:Anweis` |
| atr | ATR-2026-00148 | 3 | es | `(?i)(?:ignora\|ignorar\|olvida\|olvidar)\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones\|ind` |
| atr | ATR-2026-00148 | 4 | es | `(?i)(?:sin\|sin\s+ninguna?)\s+(?:restricciones\|limitaciones\|filtros\|censura)` |
| atr | ATR-2026-00148 | 5 | ja | `(?:制限のない\|制限なし\|制約のない\|制約なし\|倫理的な制約).*(?:AI\|アシスタント\|エージェント)` |
| atr | ATR-2026-01013 | 0 | es | `(?i)(¿?(cu[aá]l\s+es\|d[ií]me\|proporciona\|comparte)\s+(la\|tu\|el)\s+(contrase[ñn]a\|cla` |
| atr | ATR-2026-01013 | 1 | fr | `(?i)(quel\s+est\s+le\s+(mot\s+de\s+passe\|code\s+secret\|code\s+d.acc[eè]s\|identifiant)\|` |
| atr | ATR-2026-01013 | 2 | it | `(?i)(qual\s+[eè]\s+(la\s+)?(password\|parola\s+d.ordine\|codice\s*segreto\|pin\b\|chiave\s` |
| atr | ATR-2026-01013 | 3 | de | `(?i)(was\s+ist\s+(das\s+)?(passwort\|geheimnis\|geheimschl[uü]ssel\|pin\b\|zugangsco[de])\` |
| atr | ATR-2026-01013 | 4 | ja | `(パスワード\|暗証番号\|秘密の言葉\|アクセスコード\|秘密鍵\|パスコード).{0,20}(は何\|を教えて\|を教えろ\|を教えなさい\|を共有\|を確認\|を入力)` |
| atr | ATR-2026-01013 | 5 | pt | `(?i)(qual\s+[eé]\s+(a\s+)?(senha\|palavra[\s-]passe\|c[oó]digo\s*secreto\|pin\b)\|me\s+d[e` |
| atr | ATR-2026-01013 | 6 | nl | `(?i)(wat\s+is\s+(het\s+)?(wachtwoord\|geheime\s+sleutel\|pincode\|toegangscode)\|vertel\s+` |
| atr | ATR-2026-01013 | 7 | ru | `(какой\|что\s+такое\|скажи\|сообщи\|дай).{0,20}(пароль\|секретный\s+ключ\|код\s+доступа\|п` |
| atr | ATR-2026-01013 | 8 | tr | `(?i)(şifre\|parola\|gizli\s+anahtar\|erişim\s+kodu).{0,30}(nedir\|ne\|söyle\|paylaş\|ver)` |
| atr | ATR-2026-01013 | 10 | ko | `(비밀번호\|패스워드\|패스코드\|접근코드\|비밀키).{0,20}(가\s*(무엇\|뭐\|뭔지\|어떻게)\|를\s*(알려\|공유\|말해\|입력))` |
| atr | ATR-2026-01013 | 11 | ar | `(ما\s+هي\|أخبرني\|أعطني\|شارك).{0,20}(كلمة\s+المرور\|رمز\s+السر\|المفتاح\s+السري\|رمز\s+ال` |
| atr | ATR-2026-01013 | 12 | hi | `(पासवर्ड\|गुप्त\s+कुंजी\|एक्सेस\s+कोड).{0,20}(क्या\s+है\|बताओ\|दो\|साझा)` |
| atr | ATR-2026-02230 | 1 | de | `(?i)\bwenn\s+['"]?\w{2,20}['"]?\s+gesagt\s+wird\b[\s\S]{0,30}\bist\s+(die\s+)?richtig\w*\s` |
| atr | ATR-2026-02230 | 4 | es | `(?i)\bsi\s+yo\s+digo\s+[\wáéíóúñ]{2,20}\b[\s\S]{0,20}\btu\s+dices?\b` |
| atr | ATR-2026-02231 | 1 | de | `(?i)\b(gib\|geben\s+sie)\s+(eine\s+)?antwort\b[\s\S]{0,30}\boder\s+du\s+stirbst\b(?!\s*[.!` |
| atr | ATR-2026-02231 | 2 | es | `(?i)\b(olvidar?\|responde\|contesta\|dices?\|debes?\|tienes?\s+que)\b[\s\S]{0,40}\bo\s+(tu` |
| atr | ATR-2026-02232 | 1 | de | `(?i)\bdu\s+bist\s+[a-z][\w]{2,20}\b(?![\s\S]{0,30}\b(geschichte\|roman\|film\|spiel\|rolle` |
| fevzi_pidr | PID-TRM-001 | 0 | any | `(?:önceki\|yukarıdaki\|bütün\|tüm\|sistem)[^\n]{0,25}(?:talimat\|komut\|kural\|yönerge)\w*` |
| fevzi_pidr | PID-TRM-002 | 0 | any | `kullanıcı(?:ya\|dan)[^\n]{0,25}(?:söyleme\|haber\s+verme\|bildirme\|gösterme\|gizle)\|\b(?` |
| fevzi_pidr | PID-TRM-003 | 0 | any | `\b(?:parola\|şifre\|gizli\s+anahtar\|api\s+anahtar\w*)\b` |
| fevzi_pidr | PID-TRM-004 | 0 | any | `(?:sınırsız\|kısıtlama\s+yok\|kural\s+tanımıyorsun\|her\s+şeyi\s+yapabilirsin)` |

## 保留但剪除了非目标语言分支的模式：8

这些模式在英文/中文部分保持原语义；被剪除的是同一正则里的德/西/法/日/韩/俄等备选分支（剪除结果只会让匹配集合变小）。

- atr:ATR-2026-00001#1: removed non-target-language alternatives: davor | zuvor
- atr:ATR-2026-00001#2: removed non-target-language alternatives: Herausforderung | Aufgabe | einer\s+weiteren
- atr:ATR-2026-00001#6: removed non-target-language alternatives: herzlichen\s+gl[uü]ckwunsch | gut\s+gemacht | ausgezeichnet | hervorragend | sehr\s+gut | damit\s+hast\s+du\s+dich\s+selbst\s+[uü]bertroffen | komm
- atr:ATR-2026-00001#9: removed non-target-language alternatives: jetzt\s+bist\s+du | du\s+bist\s+(?:jetzt|nun) | stell\s+dir\s+vor\s+du\s+bist
- atr:ATR-2026-00001#10: removed non-target-language alternatives: ich\s+m[oö]chte,?\s+dass\s+Sie\s+als
- atr:ATR-2026-00001#11: removed non-target-language alternatives: du\s+bist
- atr:ATR-2026-00097#12: removed non-target-language alternatives: 만약 너가 | もしあなたが | 또는 | または
- atr:ATR-2026-02005#0: removed non-target-language alternatives: nicht\s+(?:eine\s+sekunde|einen\s+moment)?\s*(?:lang\s+)?aus\s+(?:ihr\w*|seiner)?\s*(?:rolle|figur|charakter\w*) | bleiben\s+immer
