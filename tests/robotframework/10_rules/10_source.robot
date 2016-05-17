| * Settings *  | *Value*           |
| Documentation | Source tests      |
| Library       | BuiltIn           |
| Library       | OperatingSystem   |
| Library       | Process           |
| Library       | String            |
| Library       | Selenium2Library  |
| Library       | Screenshot        |
| Resource      | common.robot      |
| Resource      | source.robot      |
| Resource      | settings.robot    |
| Force Tags    | source            |
| Test Setup    | Source Test Setup |
| Test Teardown | Common Teardown   |

| *Test Cases*       |                 |                              |                    |                                          |
| Test source create | [Documentation] | Test default source creation |                    |                                          |
|                    | [Tags]          | default                      |                    |                                          |
|                    | Create source   |                              |                    |                                          |
| *Test Cases*       |                 |                              |                    |                                          |
| Valid sources      | [Documentation] | Test valid sources           |                    |                                          |
|                    | Create source   | name=SourceFileTarGz         | file=${RULES_FILE} | datatype=Signatures files in tar archive |
#|               | Create source     | name=SourceUrlTarGz  | method=url         | datatype=Signatures files in tar archive |
#| Invalid sources | [Documentation] | Test invalid sources |
#|               | Run Keyword And Expect Error | * | Create source | name=invalid_url | url=${EMPTY}

| Duplicated sources | [Documentation]              | Test source uniqueness |               |
|                    | Create source                |                        |               |
|                    | Run Keyword And Expect Error | *                      | Create source |
|                    | Delete source                |                        |               |

| *Keyword*         |              |
| Source Test Setup | Common Setup |
|                   | Set Proxy    |
