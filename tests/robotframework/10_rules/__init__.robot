| * Settings *  |                     |
| Documentation | Scirius rules tests |
| Library       | OperatingSystem     |
| Library       | Process             |
| Resource      | ../config.txt       |
| Suite Setup   | Suite Setup         |

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
