/**
 * Language Generator
 */
const { exec } = require('child_process');
const fs = require('fs');

function languageIsSupported(language) {
  try {
    fs.accessSync(`app/translations/${language}.json`, fs.F_OK);
    return true;
  } catch (e) {
    return false;
  }
}

module.exports = {
  description: 'Add a language',
  prompts: [
    {
      type: 'input',
      name: 'language',
      message:
        'What is the language you want to add i18n support for (e.g. "fr", "de")?',
      default: 'fr',
      validate: value => {
        if (/.+/.test(value) && value.length === 2) {
          return languageIsSupported(value)
            ? `The language "${value}" is already supported.`
            : true;
        }

        return '2 character language specifier is required';
      },
    },
  ],

  actions: ({ test }) => {
    const actions = [];

    if (test) {
      // backup files that will be modified so we can restore them
      actions.push({
        type: 'backup',
        path: '../../app',
        file: 'i18n.js',
      });

      actions.push({
        type: 'backup',
        path: '../../app',
        file: 'app.js',
      });
    }

    actions.push({
      type: 'modify',
      path: '../../app/i18n.js',
      pattern: /(const ..LocaleData = require\('react-intl\/locale-data\/..'\);\n)+/g,
      templateFile: './language/intl-locale-data.hbs',
    });
    actions.push({
      type: 'modify',
      path: '../../app/i18n.js',
      pattern: /(\s+'[a-z]+',\n)(?!.*\s+'[a-z]+',)/g,
      templateFile: './language/app-locale.hbs',
    });
    actions.push({
      type: 'modify',
      path: '../../app/i18n.js',
      pattern: /(const ..TranslationMessages = require\('\.\/translations\/..\.json'\);\n)(?!const ..TranslationMessages = require\('\.\/translations\/..\.json'\);\n)/g,
      templateFile: './language/translation-messages.hbs',
    });
    actions.push({
      type: 'modify',
      path: '../../app/i18n.js',
      pattern: /(addLocaleData\([a-z]+LocaleData\);\n)(?!.*addLocaleData\([a-z]+LocaleData\);)/g,
      templateFile: './language/add-locale-data.hbs',
    });
    actions.push({
      type: 'modify',
      path: '../../app/i18n.js',
      pattern: /([a-z]+:\sformatTranslationMessages\('[a-z]+',\s[a-z]+TranslationMessages\),\n)(?!.*[a-z]+:\sformatTranslationMessages\('[a-z]+',\s[a-z]+TranslationMessages\),)/g,
      templateFile: './language/format-translation-messages.hbs',
    });
    actions.push({
      type: 'add',
      path: '../../app/translations/{{language}}.json',
      templateFile: './language/translations-json.hbs',
      abortOnFail: true,
    });
    actions.push({
      type: 'modify',
      path: '../../app/app.js',
      pattern: /(import\('intl\/locale-data\/jsonp\/[a-z]+\.js'\),\n)(?!.*import\('intl\/locale-data\/jsonp\/[a-z]+\.js'\),)/g,
      templateFile: './language/polyfill-intl-locale.hbs',
    });

    if (!test) {
      actions.push(() => {
        const cmd = 'npm run extract-intl';
        exec(cmd, (err, result) => {
          if (err) throw err;
          process.stdout.write(result);
        });
        return 'modify translation messages';
      });
    }

    return actions;
  },
};
