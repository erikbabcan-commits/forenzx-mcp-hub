# ILUMINAT — balík pre Groka

Samostatný offline návrh obrazovky `youh4ck3dme | lockdown` a pokyny na audit
Windows 11 pred prípadným nasadením. **HTML nie je bezpečnostný zámok PC.**

## Grok: začni tu

Prečítaj celý [GROK-HANDOFF.txt](GROK-HANDOFF.txt). Vykonaj iba read-only audit
oprávnene spravovaného počítača a predlož plán. Pred inštaláciou, autostartom,
zmenami prihlasovania alebo šifrovaním čakaj na výslovný súhlas vlastníka.
Samotné zverejnenie tohto balíka na GitHube taký súhlas nepredstavuje.

Ak máš iba chat bez prístupu k PC, priprav konkrétne príkazy a netvrď, že si ich
spustil. Nevykonávaj nastavenie ostatných aplikácií v tomto repozitári.

## Obsah

| Súbor | Účel |
| --- | --- |
| [GROK-HANDOFF.txt](GROK-HANDOFF.txt) | Zadanie, obmedzenia a postup A–E |
| [preview/index.html](preview/index.html) | Čierny 8-bitový terminálový vzhľad |
| [TEST-RESULTS.md](TEST-RESULTS.md) | Vykonané testy a neoverené časti |
| [checks/verify-preview.cjs](checks/verify-preview.cjs) | Opakovateľná kontrola JavaScript logiky bez prehliadača |

## Otvorenie náhľadu

Stiahni `preview/index.html` a otvor ho v modernom prehliadači. Nepotrebuje server,
inštaláciu, externé knižnice ani internet. Na GitHube sa HTML zobrazuje ako zdrojový
kód. Po stiahnutí ho možno uložiť napríklad do priečinka
`Desktop\_ILUMINAT\security\lockdown\preview\` svojho účtu mimo Git checkoutov.

Použi ľubovoľný nesúkromný skúšobný text. **Každý neprázdny vstup prehrá tú istú
ukážku odomknutia.** Nevkladaj skutočné heslo, Windows PIN ani recovery kľúč.
Vstup sa neukladá, neloguje ani neodosiela a po potvrdení sa vyprázdni.
Voliteľnú celú obrazovku možno zapnúť kliknutím a opustiť cez Esc.

## Overenie balíka

Ak je k dispozícii Node.js, z tohto priečinka spusti:

```text
node checks/verify-preview.cjs
```

Kontrola spustí JavaScript s pamäťovým adaptérom DOM a preverí správanie ukážky.
Nekontroluje vykreslenie, oprávnenia fullscreen API ani bezpečnosť Windows.
Podrobnosti sú v [TEST-RESULTS.md](TEST-RESULTS.md).

## Stav pripravenosti

Pripravené: dizajn, odovzdanie zadania a kontroly ukážky.

Nasadenie na Windows, audit cieľového PC, šifrovanie, systémové prihlasovanie,
Scheduled Task, watchdog a test reštartu: **NOT_VERIFIED / nevykonané**.
Inštalačné PowerShell skripty zatiaľ nie sú súčasťou balíka; podľa zadania ich má
agent pripraviť až po audite a príslušnom výslovnom súhlase.

Ochranu pred prihlásením zabezpečuje systémové prihlásenie Windows. Úloha
`At log on` sa spustí až po prihlásení a môže mať oneskorenie. Bežné HTML ani
Topmost okno nezablokujú Ctrl+Alt+Del a nenahrádzajú systémové uzamknutie.
