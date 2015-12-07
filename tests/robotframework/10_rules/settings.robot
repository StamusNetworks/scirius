| *Keyword* |                  |                                |                        |                   |
| Set Proxy | [Documentation]  | Set the proxy                  |                        |                   |
|           | [Arguments]      | ${enable}=${ENALE_PROXY}       | ${proxy}=${HTTP_PROXY} |                   |
|           | Go To            | ${BASE_URL}rules/settings/     |                        |                   |
|           | ${proxy}=        | Set Variable If                | ${enable} == 0         | ${EMPTY}          |
|           | Select Checkbox  | id_use_http_proxy              |                        |                   |
|           | Input Text       | id_http_proxy                  | ${proxy}               |                   |
|           | Input Text       | id_https_proxy                 | ${proxy}               |                   |
|           | Run Keyword If   | ${enable} == 0                 | Unselect Checkbox      | id_use_http_proxy |
|           | Run Keyword If   | ${enable} == 1                 | Select Checkbox        | id_use_http_proxy |
|           | Debug Screenshot |                                |                        |                   |
|           | Click Element    | xpath=//button[@type='submit'] |                        |                   |
|           | Debug Screenshot |                                |                        |                   |
