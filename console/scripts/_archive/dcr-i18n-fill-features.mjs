#!/usr/bin/env node
//
// One-shot fill for the SETTING.FEATURES.DYNAMICCLIENTREGISTRATION{,DESCRIPTION}
// keys in 21 non-en locale files. cavekit-feature-flag-dcr-runtime.md R8
// (T-006 in the kit's dispatch order). Same overwrite-on-passthrough
// semantic as the prior dcr-i18n-fill-extended.mjs — only writes when
// the current value matches the EN source verbatim.

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const I18N_DIR = resolve(__dirname, '..', '..', 'src/assets/i18n');

// Translations for SETTING.FEATURES.DYNAMICCLIENTREGISTRATION{_DESCRIPTION}.
// Glossary preserved: OAuth, OIDC, RFC 7591.
const T = {
  ar: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'يسمح لعملاء OAuth/OIDC بتسجيل أنفسهم وقت التشغيل عبر /oidc/v1/register (RFC 7591). يجب أن تكون بوابة yaml (OIDC.DCR.Enabled) مفعلة أيضًا؛ كلتا البوابتين تعملان معًا (AND).',
  },
  bg: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Позволява на OAuth/OIDC клиенти да се регистрират сами по време на изпълнение чрез /oidc/v1/register (RFC 7591). yaml портата (OIDC.DCR.Enabled) също трябва да е включена; и двете порти AND заедно.',
  },
  cs: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Umožňuje OAuth/OIDC klientům, aby se sami registrovali za běhu přes /oidc/v1/register (RFC 7591). yaml brána (OIDC.DCR.Enabled) také musí být zapnutá; obě brány spojené AND.',
  },
  de: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Erlaubt OAuth/OIDC-Clients, sich zur Laufzeit selbst über /oidc/v1/register (RFC 7591) zu registrieren. Das yaml-Gate (OIDC.DCR.Enabled) muss ebenfalls aktiv sein; beide Gates UND-verknüpft.',
  },
  es: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Permite a los clientes OAuth/OIDC registrarse en tiempo de ejecución vía /oidc/v1/register (RFC 7591). La puerta yaml (OIDC.DCR.Enabled) también debe estar activa; ambas puertas Y juntas.',
  },
  fr: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: "Autorise les clients OAuth/OIDC à s'enregistrer à l'exécution via /oidc/v1/register (RFC 7591). La porte yaml (OIDC.DCR.Enabled) doit aussi être activée ; les deux portes ET ensemble.",
  },
  hu: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Engedélyezi az OAuth/OIDC-klienseknek, hogy futás közben regisztrálják magukat a /oidc/v1/register (RFC 7591) végponton. A yaml-kapunak (OIDC.DCR.Enabled) is bekapcsolva kell lennie; a két kapu ÉS-kapcsolatban van.',
  },
  id: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Mengizinkan klien OAuth/OIDC mendaftarkan diri saat runtime melalui /oidc/v1/register (RFC 7591). Gerbang yaml (OIDC.DCR.Enabled) juga harus aktif; kedua gerbang DAN bersama.',
  },
  it: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Consente ai client OAuth/OIDC di registrarsi a runtime tramite /oidc/v1/register (RFC 7591). Il gate yaml (OIDC.DCR.Enabled) deve essere anche attivo; entrambi i gate in AND.',
  },
  ja: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'OAuth/OIDC クライアントが /oidc/v1/register (RFC 7591) を介して実行時に自己登録することを許可します。yaml ゲート (OIDC.DCR.Enabled) も有効である必要があります。両ゲートが AND で結合されます。',
  },
  ko: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'OAuth/OIDC 클라이언트가 /oidc/v1/register (RFC 7591)를 통해 런타임에 자체 등록할 수 있도록 허용합니다. yaml 게이트(OIDC.DCR.Enabled)도 켜져 있어야 하며, 두 게이트가 AND로 결합됩니다.',
  },
  mk: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Дозволува на OAuth/OIDC клиентите сами да се регистрираат во време на извршување преку /oidc/v1/register (RFC 7591). yaml портата (OIDC.DCR.Enabled) исто така мора да биде вклучена; двете порти AND заедно.',
  },
  nl: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Staat OAuth/OIDC-clients toe zich tijdens runtime te registreren via /oidc/v1/register (RFC 7591). De yaml-gate (OIDC.DCR.Enabled) moet ook aan staan; beide gates EN samen.',
  },
  pl: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Pozwala klientom OAuth/OIDC zarejestrować się w czasie wykonywania przez /oidc/v1/register (RFC 7591). Brama yaml (OIDC.DCR.Enabled) również musi być włączona; obie bramy I razem.',
  },
  pt: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Permite que clientes OAuth/OIDC se registem em tempo de execução via /oidc/v1/register (RFC 7591). A porta yaml (OIDC.DCR.Enabled) também tem de estar ativa; ambas as portas E juntas.',
  },
  ro: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Permite clienților OAuth/OIDC să se înregistreze la runtime prin /oidc/v1/register (RFC 7591). Poarta yaml (OIDC.DCR.Enabled) trebuie să fie de asemenea activată; ambele porți combinate prin ȘI.',
  },
  ru: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Разрешает клиентам OAuth/OIDC самостоятельно регистрироваться во время выполнения через /oidc/v1/register (RFC 7591). yaml-врата (OIDC.DCR.Enabled) также должна быть включена; обе вратa объединяются И.',
  },
  sv: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Tillåter OAuth/OIDC-klienter att registrera sig vid körning via /oidc/v1/register (RFC 7591). yaml-grinden (OIDC.DCR.Enabled) måste också vara på; båda grindarna OCH tillsammans.',
  },
  tr: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'OAuth/OIDC istemcilerinin çalışma zamanında /oidc/v1/register (RFC 7591) üzerinden kendilerini kaydetmesine izin verir. yaml kapısı (OIDC.DCR.Enabled) da açık olmalı; her iki kapı VE ile birleşir.',
  },
  uk: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: 'Дозволяє клієнтам OAuth/OIDC реєструватися самостійно під час виконання через /oidc/v1/register (RFC 7591). yaml-брама (OIDC.DCR.Enabled) також має бути ввімкнена; обидві брами об\'єднано через І.',
  },
  zh: {
    DYNAMICCLIENTREGISTRATION: 'Dynamic Client Registration',
    DYNAMICCLIENTREGISTRATION_DESCRIPTION: '允许 OAuth/OIDC 客户端在运行时通过 /oidc/v1/register (RFC 7591) 自行注册。yaml 闸门 (OIDC.DCR.Enabled) 也必须开启；两个闸门以 AND 连接。',
  },
};

async function main() {
  for (const [locale, kv] of Object.entries(T)) {
    const path = join(I18N_DIR, locale + '.json');
    const data = JSON.parse(await readFile(path, 'utf8'));
    if (!data.SETTING?.FEATURES) {
      process.stderr.write(`skipping ${locale}: SETTING.FEATURES missing\n`);
      continue;
    }
    let writes = 0;
    for (const [k, v] of Object.entries(kv)) {
      if (data.SETTING.FEATURES[k] === undefined) {
        data.SETTING.FEATURES[k] = v;
        writes++;
      }
    }
    await writeFile(path, JSON.stringify(data, null, 2) + '\n', 'utf8');
    process.stderr.write(`wrote ${locale} (${writes} keys)\n`);
  }
}

main().catch(err => { process.stderr.write(`fatal: ${err.message}\n`); process.exit(1); });
