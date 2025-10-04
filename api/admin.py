from django.contrib import admin
from .models import (
    User, Journal, Article, Issue, ArticleVersion, ArticleTag, AuditLog,
    IntegrationSetting, JournalCategory, JournalType, EditorialBoardApplication,
    ClickTransaction, Service, ServiceOrder
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

class ClickTransactionAdmin(admin.ModelAdmin):
    list_display = ('merchant_trans_id', 'user', 'amount', 'status', 'created_at')
    list_filter = ('status',)
    search_fields = ('merchant_trans_id', 'user__phone')

class ServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'price', 'is_active')
    prepopulated_fields = {'slug': ('name',)}

class ServiceOrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'service', 'status', 'created_at')
    list_filter = ('status', 'service')
    search_fields = ('user__phone', 'service__name')


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
admin.site.register(ClickTransaction, ClickTransactionAdmin)
admin.site.register(Service, ServiceAdmin)
admin.site.register(ServiceOrder, ServiceOrderAdmin)