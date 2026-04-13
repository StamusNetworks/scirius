setup:
    uv venv
    source .venv/bin/activate
    uv pip install . .[appliances] .[dev]
    prek install

format:
    ruff check --fix --ignore=E501,E722 .
    ruff format --fix .

lint-all:
    prek run --all-files

check *FILES:
    ruff check --select=E,F,W,S,ASYNC,C4,ISC,ICN,PIE,PYI,RSE,RET,SLOT,TID,TC,PLE,FURB,YTT,S,C4,TID,I --ignore=E501 --exclude=appliances/migrations,appliances/south_migrations,node_modules,rules/migrations,rules/south_migrations,tests/docker/,tests/notebooks,accounts/south_migrations,suricata/south_migrations,suricata/migrations,.uv-cache,.venv,rules/tests,appliances/tests,suricata/tests,stamus-docs,scirius/pytests.py,accounts/tests.py,appliances/func_tests.py {{FILES}}

fix *FILES:
    ruff check --select=E,F,W,S,ASYNC,C4,ISC,ICN,PIE,PYI,RSE,RET,SLOT,TID,TC,PLE,FURB,YTT,S,C4,TID,I --ignore=E501 --exclude=appliances/migrations,appliances/south_migrations,node_modules,rules/migrations,rules/south_migrations,tests/docker/,tests/notebooks,accounts/south_migrations,suricata/south_migrations,suricata/migrations,.uv-cache,.venv,rules/tests,appliances/tests,suricata/tests,stamus-docs,scirius/pytests.py,accounts/tests.py,appliances/func_tests.py --fix {{FILES}}

test *FILES:
    DS=tests.settings RULESET_MIDDLEWARE=appliances slipcover --source scirius,suricata,rules,appliances,volumetry --omit  "**/migrations/*.py,**/tests/*.py,**/tests.py,**/pytest*.py,**/test_*.py,**/south_migrations/*.py,appliances/func_tests.py,**/conftest.py,**/local_settings.py,**/views/*.py,**/forms/*.py,**/views.py,**/forms.py" -m pytest -vv {{FILES}}

testkw keyword:
    DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv -k {{keyword}}

test-no-cov *FILES:
    DS=tests.settings RULESET_MIDDLEWARE=appliances pytest -vv {{FILES}}
