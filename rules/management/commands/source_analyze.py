from django.core.management.base import BaseCommand
from rules.models import Source, TestRules, RuleAtVersion


class Command(BaseCommand):
    help = 'Analyze rules from one or all sources'

    def add_arguments(self, parser):
        parser.add_argument('source', help='Source name. All sources if no flag.', default=None, nargs='?')

    def handle(self, *args, **options):
        source_name = options.get('source', None)

        sources = Source.objects.all()
        if source_name:
            sources = sources.filter(name=source_name)

        for source in sources:
            testor = TestRules()
            related_files, cats_content, iprep_content = source.prepare_tests_files()

            all_versions = RuleAtVersion.get_versions_to_analyse()
            for version in all_versions:
                contents = RuleAtVersion.objects. \
                    filter(
                        rule__category__source=source,
                        version=version
                    ).distinct().values_list('content', flat=True)

                if contents:
                    content = testor.rules_infos(
                        '\n'.join(contents),
                        related_files=related_files,
                        cats_content=cats_content,
                        iprep_content=iprep_content
                    )
                    RuleAtVersion.write_analyse(content, version)
