| * Settings * |                |
| Resource     | ../config.txt  |
| Resource     | settings.robot |

| *Keyword*           |                        |                                                                   |                       |
| Suite Setup         | [Documentation]        | Set basic configuration                                           |                       |
|                     | Download test rules    |                                                                   |                       |
| Download test rules | [Documentation]        | Download rules if required                                        |                       |
|                     | [Arguments]            | ${url}=${RULES_URL}                                               | ${file}=${RULES_FILE} |
|                     | Run Process            | test -d ${CACHE_DIR} \|\| mkdir ${CACHE_DIR}                      | shell=True            |
|                     | Directory Should Exist | ${CACHE_DIR}                                                      |                       |
|                     | Run Process            | test -e ${file} \|\| wget -O ${file} ${url}                       | shell=True            |
|                     | File Should Exist      | ${file}                                                           |                       |
|                     | Run Process            | test -d ${CACHE_DIR}rules/ \|\| tar -C ${CACHE_DIR} -xvzf ${file} | shell=True            |
|                     | Directory Should Exist | ${CACHE_DIR}rules/                                                |                       |
|                     | File Should Exist      | ${CACHE_DIR}rules/emerging-telnet.rules                           |                       |

| Common Setup     | Open Browser        | ${BASE_URL}                             |                         |
|                  | Scirius Login       |                                         |                         |
|                  | Set Proxy           |                                         |                         |
| Common Teardown  | Clean sources       |                                         |                         |
|                  | Close Browser       |                                         |                         |
| Scirius Login    | [Documentation]     | Login as user                           |                         |
|                  | [Arguments]         | ${user}=${DEFAULT_USER}                 | ${pass}=${DEFAULT_PASS} |
|                  | Go To               | ${BASE_URL}                             |                         |
|                  | Debug Screenshot    |                                         |                         |
|                  | Input Text          | id_username                             | ${user}                 |
|                  | Input Text          | id_password                             | ${pass}                 |
|                  | Submit Form         |                                         |                         |
|                  | Page Should Contain | Logged in as ${user}                    |                         |
| Logout           | [Documentation]     | Logout                                  |                         |
|                  | Go To               | ${BASE_URL}                             |                         |
|                  | Click Element       | id=logo                                 |                         |
|                  | Click Element       | link=Logout                             |                         |
|                  | Page Should Contain | Login to Scirius                        |                         |
| Debug Screenshot | [Documentation]     | Take a screenshot when debug is enabled |                         |
|                  | Run Keyword If      | ${DEBUG} == 1                           | Capture Page Screenshot |
