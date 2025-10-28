# File: api/management/commands/create_services.py

from django.core.management.base import BaseCommand
from api.models import Service

class Command(BaseCommand):
    help = 'Create all required services in the database'

    def handle(self, *args, **options):
        services_data = [
            {
                'name': 'AI Document Utilities',
                'slug': 'ai-document-utilities',
                'description': 'AI-powered document utilities including text analysis, summarization, and enhancement tools',
                'price': 15000.00,
                'is_active': True
            },
            {
                'name': 'Article Writing',
                'slug': 'article-writing',
                'description': 'Professional article writing services with expert authors',
                'price': 50000.00,
                'is_active': True
            },
            {
                'name': 'Co-Author Management',
                'slug': 'coauthor-management',
                'description': 'Manage co-authors for your publications and collaborative works',
                'price': 10000.00,
                'is_active': True
            },
            {
                'name': 'Document Preview',
                'slug': 'document-preview',
                'description': 'Preview your documents before submission with professional formatting',
                'price': 5000.00,
                'is_active': True
            },
            {
                'name': 'Editor Communication',
                'slug': 'editor-communication',
                'description': 'Direct communication channel with journal editors',
                'price': 8000.00,
                'is_active': True
            },
            {
                'name': 'Google Scholar Indexing',
                'slug': 'google-scholar-indexing',
                'description': 'Index your publications in Google Scholar for better visibility',
                'price': 25000.00,
                'is_active': True
            },
            {
                'name': 'Literacy Check',
                'slug': 'literacy-check',
                'description': 'Comprehensive literacy and language quality check for your documents',
                'price': 12000.00,
                'is_active': True
            },
            {
                'name': 'ORCID Integration',
                'slug': 'orcid-integration',
                'description': 'Integration with ORCID for author identification and publication tracking',
                'price': 7000.00,
                'is_active': True
            },
            {
                'name': 'Plagiarism Check',
                'slug': 'plagiarism-check',
                'description': 'Advanced plagiarism detection and reporting service',
                'price': 20000.00,
                'is_active': True
            },
            {
                'name': 'Printed Publications',
                'slug': 'printed-publications',
                'description': 'Professional printing and hardcopy publication services',
                'price': 100000.00,
                'is_active': True
            },
            {
                'name': 'Statistical Reports',
                'slug': 'statistical-reports',
                'description': 'Generate detailed statistical reports for your research data',
                'price': 30000.00,
                'is_active': True
            },
            {
                'name': 'UDC Classification',
                'slug': 'udc-classification',
                'description': 'Universal Decimal Classification assignment for your publications',
                'price': 15000.00,
                'is_active': True
            }
        ]

        created_count = 0
        existing_count = 0

        for service_data in services_data:
            try:
                service, created = Service.objects.get_or_create(
                    slug=service_data['slug'],
                    defaults=service_data
                )
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f'Created service: {service.name}')
                    )
                    created_count += 1
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Service already exists: {service.name}')
                    )
                    existing_count += 1
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error creating service {service_data["name"]}: {str(e)}')
                )

        self.stdout.write(
            self.style.SUCCESS(
                f'\nService creation complete!\n'
                f'Created: {created_count} services\n'
                f'Already existed: {existing_count} services\n'
                f'Total services in database: {Service.objects.count()}'
            )
        )