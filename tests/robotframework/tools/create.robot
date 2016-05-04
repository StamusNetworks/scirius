| * Settings * | *Value*                          |
| Resource     | ../10_rules/common.robot         |
| Resource     | ../10_rules/source.robot         |
| Resource     | ../10_rules/ruleset.robot        |
| Resource     | ../10_rules/es.robot             |

| *Test Cases*    |                  |             |                                          |                    |
| Create a source |                  |             |                                          |                    |
|                 | [Tags]           | create      | create_source                            |                    |
|                 | Common Setup     |             |                                          |                    |
|                 | Create source    | method=file | datatype=Signatures files in tar archive | file=${RULES_FILE} |

| Create a ruleset | [Tags]         | create | create_ruleset |
|                  | Create ruleset |        |                |
