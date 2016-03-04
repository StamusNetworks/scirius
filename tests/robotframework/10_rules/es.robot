| *Setting* | *Value*  |
| Library   | String   |
| Library   | DateTime |

| *Keyword*      |                               |                                  |                                  |                                  |           |   |
| Check ES stats | [Documentation]               | Check data was logged in ES      |                                  |                                  |           |   |
|                | [Arguments]                   | ${logstash_prefix}=logstash-ssh- | ${add_date}=1                    |                                  |           |   |
|                | SN Go To                      | ${BASE_URL}rules/es              |                                  |                                  |           |   |
|                | SN Click Element              | xpath=//a[@href='#indices']      |                                  |                                  |           |   |
|                | Wait until Element is visible | xpath=//table[@class='paleblue'] |                                  |                                  |           |   |
|                | Debug Screenshot              |                                  |                                  |                                  |           |   |
|                | ${prefix}=                    | _ES add date                     | prefix=${logstash_prefix}        |                                  |           |   |
|                | ${prefix}=                    | Set Variable If                  | ${add_date} == 0                 | ${logstash_prefix}               | ${prefix} |   |
|                | :FOR                          | ${i}                             | IN RANGE                         | 64                               |           |   |
|                | \                             | ${cell}=                         | Get Table Cell                   | xpath=//table[@class='paleblue'] | ${i}      | 1 |
|                | \                             | Exit for loop if                 | '${cell}' == '${prefix}'         |                                  |           |   |
|                | Should be equal               | ${cell}                          | ${prefix}                        |                                  |           |   |
|                | ${count}=                     | Get Table Cell                   | xpath=//table[@class='paleblue'] | ${i}                             | 2         |   |
|                | Should not be equal           | ${count}                         | 0                                |                                  |           |   |
|                | Debug Screenshot              |                                  |                                  |                                  |           |   |

| _ES add date | [Documentation]     | Add the date of the current to a logstash prefix |                |           |            |   |            |   |            |
|              | [Arguments]         | ${prefix}                                        |                |           |            |   |            |   |            |
|              | @{date}=            | Get Time                                         | year month day |           |            |   |            |   |            |
|              | ${_date}=           | Catenate                                         | SEPARATOR=     | ${prefix} | ${date[0]} | . | ${date[1]} | . | ${date[2]} |
|              | Return From Keyword | ${_date}                                         |                |           |            |   |            |   |            |
