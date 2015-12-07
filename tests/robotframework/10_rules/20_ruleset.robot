| * Settings *  | *Value*          |
| Documentation | Ruleset tests    |
| Library       | BuiltIn          |
| Library       | OperatingSystem  |
| Library       | Process          |
| Library       | String           |
| Library       | Selenium2Library |
| Library       | Screenshot       |
| Resource      | common.robot     |
| Resource      | source.robot     |
| Resource      | ruleset.robot    |
| Force Tags    | ruleset          |
| Test Setup    | Setup            |
| Test Teardown | Teardown         |

| *Test Cases*        |                 |                               |
| Test ruleset create | [Documentation] | Test default ruleset creation |
|                     | [Tags]          | default                       |
|                     | Create ruleset  |                               |

| *Test Cases*    |                              |                      |                        |                    |                 |
| Valids ruleset  | [Documentation]              | Test valids ruleset  |                        |                    |                 |
|                 | Create source                | name=SourceFileTarGz | method=file            | file=${RULES_FILE} |                 |
|                 | Create ruleset               | name=RulesetTarGzSrc | source=SourceFileTarGz |                    |                 |
| Invalid ruleset | [Documentation]              | Test invalid ruleset |                        |                    |                 |
|                 | Run Keyword And Expect Error | *                    | Create ruleset         | name=no_source     | source=${EMPTY} |

| *Keyword* |                 |
| Setup     | Common Setup    |
|           | Create source   |
| Teardown  | Clean rulesets  |
|           | Common Teardown |
