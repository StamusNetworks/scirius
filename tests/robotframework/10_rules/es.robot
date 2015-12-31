| *Setting* | *Value*  |
| Library   | String   |
| Library   | DateTime |

| *Keyword*      |                     |                                  |                                  |                                  |              |   |               |   |             |
| Check ES stats | [Documentation]     | Check data was logged in ES      |                                  |                                  |              |   |               |   |             |
|                | [Arguments]         | ${logstash_prefix}=logstash-ssh- |                                  |                                  |              |   |               |   |             |
|                | Go To               | ${BASE_URL}rules/es              |                                  |                                  |              |   |               |   |             |
|                | Click Element       | xpath=//a[@href='#indices']      |                                  |                                  |              |   |               |   |             |
|                | Debug Screenshot    |                                  |                                  |                                  |              |   |               |   |             |
|                | ${date}=            | Get Current Date                 | result_format=datetime           |                                  |              |   |               |   |             |
|                | ${idx}=             | Catenate                         | SEPARATOR=                       | ${logstash_prefix}               | ${date.year} | . | ${date.month} | . | ${date.day} |
|                | :FOR                | ${i}                             | IN RANGE                         | 64                               |              |   |               |   |             |
|                | \                   | ${cell}=                         | Get Table Cell                   | xpath=//table[@class='paleblue'] | ${i}         | 1 |               |   |             |
|                | \                   | Exit for loop if                 | '${cell}' == '${idx}'            |                                  |              |   |               |   |             |
|                | Should be equal     | ${cell}                          | ${idx}                           |                                  |              |   |               |   |             |
|                | ${count}=           | Get Table Cell                   | xpath=//table[@class='paleblue'] | ${i}                             | 2            |   |               |   |             |
|                | Should not be equal | ${count}                         | 0                                |                                  |              |   |               |   |             |
|                | Debug Screenshot    |                                  |                                  |                                  |              |   |               |   |             |
