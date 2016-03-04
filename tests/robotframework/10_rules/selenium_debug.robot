| *Keyword* |                 |                              |
| SN Go To  | [Documentation] | Go to url and perform checks |
|           | [Arguments]     | ${url}                       |
|           | Check Page      |                              |
|           | Go To           | ${url}                       |
|           | Check Page      |                              |

| SN Click Element | [Documentation] | Click Element and perform checks |
|                  | [Arguments]     | ${element}                       |
|                  | Check Page      |                                  |
|                  | Click Element   | ${element}                       |
|                  | Check Page      |                                  |

| Check page | [Documentation]         | Perform simple checks |        |
|            | Run keyword If          | ${DEBUG} == 0         | Return |
|            | Page Should Not Contain | Traceback             |        |
|            | Page Should Not Contain | Page not found        |        |
|            | Page Should Not Contain | Not found             |        |
|            | Page Should Not Contain | nginx                 |        |
