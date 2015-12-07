| * Settings * |                |
| Resource     | ../config.txt  |
| Resource     | settings.robot |

| *Keyword*        |                     |                                         |                         |
| Common Setup     | Open Browser        | ${BASE_URL}                             |                         |
|                  | Login               |                                         |                         |
|                  | Set Proxy           |                                         |                         |
| Common Teardown  | Clean sources       |                                         |                         |
|                  | Close Browser       |                                         |                         |
| Login            | [Documentation]     | Login as user                           |                         |
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
