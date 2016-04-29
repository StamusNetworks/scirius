| * Settings * |                      |
| Library      | Selenium2Library     |
| Resource     | ../config.txt        |
| Resource     | selenium_debug.robot |
| Resource     | source.robot         |
| Resource     | ruleset.robot        |

| *Keyword* |                 |                              |
| SN Go To  | [Documentation] | Go to url and perform checks |
|           | [Arguments]     | ${url}                       |
|           | Check Page      |                              |
|           | Go To           | ${url}                       |
|           | Check Page      |                              |
|           | Check Log File  |                              |

| SN Click Element | [Documentation] | Click Element and perform checks |
|                  | [Arguments]     | ${element}                       |
|                  | Check Page      |                                  |
|                  | Click Element   | ${element}                       |
|                  | Check Page      |                                  |
|                  | Check Log File  |                                  |

| Check page | [Documentation]         | Perform simple checks |
|            | Return From Keyword If  | ${DEBUG} == 0         |
|            | Page Should Not Contain | Page not found        |
|            | Page Should Not Contain | Not found             |
|            | Page Should Not Contain | nginx                 |
#|            | Page Should Not Contain | Traceback             |        |

| Check log file | [Documentation]            | Perform simple checks    |                   |                     |             |
|                | ${filesize}=               | Get File Size            | ${DJANGO_LOGFILE} |                     |             |
|                | ${traceback}=              | OperatingSystem.Get File | ${DJANGO_LOGFILE} |                     |             |
|                | Run Keyword If             | ${filesize} != 0         | Log               | ${traceback}        | level=ERROR |
|                | Run Keyword If             | ${filesize} != 0         | Remove File       | ${DJANGO_LOGFILE}   |             |
|                | Run Keyword If             | ${filesize} != 0         | Create File       | ${DJANGO_LOGFILE}   |             |
|                | Should Be Equal As Numbers | ${filesize}              | 0                 | A traceback occured |             |
