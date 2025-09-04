from django.contrib import admin
from .models import (
    User, Journal, Article, Issue, ArticleVersion, ArticleTag, AuditLog,
    IntegrationSetting, JournalCategory, JournalType, EditorialBoardApplication
)

class UserAdmin(admin.ModelAdmin):
    list_display = ('phone', 'id', 'name', 'surname', 'role', 'is_staff')
    search_fields = ('phone', 'name', 'surname')
    ordering = ('phone',)
    list_filter = ('role', 'is_staff')

class JournalAdmin(admin.ModelAdmin):
    list_display = ('name', 'journal_type', 'category', 'manager', 'regular_price', 'partner_price')
    list_filter = ('journal_type', 'category')
    search_fields = ('name', 'description')

class ArticleAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'journal', 'status', 'submissionPaymentStatus', 'plagiarism_percentage')
    list_filter = ('status', 'journal', 'submissionPaymentStatus')
    search_fields = ('title', 'author__name', 'author__surname')

class EditorialBoardApplicationAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'submitted_at')
    list_filter = ('status',)
    search_fields = ('user__name', 'user__surname')

admin.site.register(User, UserAdmin)
admin.site.register(Journal, JournalAdmin)
admin.site.register(JournalType)
admin.site.register(JournalCategory)
admin.site.register(Article, ArticleAdmin)
admin.site.register(Issue)
admin.site.register(ArticleVersion)
admin.site.register(ArticleTag)
admin.site.register(AuditLog)
admin.site.register(IntegrationSetting)
admin.site.register(EditorialBoardApplication, EditorialBoardApplicationAdmin)