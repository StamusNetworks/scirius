| * Settings * |                      |
| Resource     | ../config.txt        |
| Resource     | settings.robot       |
| Resource     | selenium_debug.robot |
| Resource     | source.robot         |
| Resource     | ruleset.robot        |

| *Keyword*           |                                        |                                                                   |                       |
| Suite Setup         | [Documentation]                        | Set basic configuration                                           |                       |
|                     | Download test rules                    |                                                                   |                       |
| Download test rules | [Documentation]                        | Download rules if required                                        |                       |
|                     | [Arguments]                            | ${url}=${RULES_URL}                                               | ${file}=${RULES_FILE} |
|                     | Run Process                            | test -d ${CACHE_DIR} \|\| mkdir ${CACHE_DIR}                      | shell=True            |
|                     | OperatingSystem.Directory Should Exist | ${CACHE_DIR}                                                      |                       |
|                     | Run Process                            | test -e ${file} \|\| wget -O ${file} ${url}                       | shell=True            |
|                     | OperatingSystem.File Should Exist      | ${file}                                                           |                       |
|                     | Run Process                            | test -d ${CACHE_DIR}rules/ \|\| tar -C ${CACHE_DIR} -xvzf ${file} | shell=True            |
|                     | OperatingSystem.Directory Should Exist | ${CACHE_DIR}rules/                                                |                       |
|                     | OperatingSystem.File Should Exist      | ${CACHE_DIR}rules/emerging-telnet.rules                           |                       |

| Common Setup     | Open Browser        | ${BASE_URL}                             | ${BROWSER}              |
|                  | Scirius Login       |                                         |                         |
| Common Teardown  | Clean sources       |                                         |                         |
|                  | Close Browser       |                                         |                         |
| Scirius Login    | [Documentation]     | Login as user                           |                         |
|                  | [Arguments]         | ${user}=${DEFAULT_USER}                 | ${pass}=${DEFAULT_PASS} |
|                  | SN Go To            | ${BASE_URL}                             |                         |
|                  | Debug Screenshot    |                                         |                         |
|                  | Input Text          | id_username                             | ${user}                 |
|                  | Input Text          | id_password                             | ${pass}                 |
|                  | Submit Form         |                                         |                         |
|                  | Page Should Contain | Logged in as ${user}                    |                         |
| Logout           | [Documentation]     | Logout                                  |                         |
|                  | SN Go To            | ${BASE_URL}                             |                         |
|                  | SN Click Element    | id=logo                                 |                         |
|                  | SN Click Element    | link=Logout                             |                         |
|                  | Page Should Contain | Login to Scirius                        |                         |
| Debug Screenshot | [Documentation]     | Take a screenshot when debug is enabled |                         |
|                  | Run Keyword If      | ${DEBUG} == 1                           | Capture Page Screenshot |
