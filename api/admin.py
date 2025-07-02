from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Journal, Article, Issue, ArticleVersion, ArticleTag, AuditLog, IntegrationSetting

class UserAdmin(BaseUserAdmin):
    model = User
    # Define fieldsets for the "change" form
    fieldsets = (
        (None, {'fields': ('phone', 'password')}),
        ('Personal Info', {'fields': ('name', 'surname', 'role', 'language', 'orcidId')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    # Define add_fieldsets for the "add" form
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'name', 'surname', 'role', 'language', 'password1', 'password2'),
        }),
    )
    list_display = ('phone', 'id', 'name', 'surname', 'role', 'is_staff')
    search_fields = ('phone', 'name', 'surname')
    ordering = ('phone',)
    # Specify the field used for authentication (replace username)
    filter_horizontal = ('groups', 'user_permissions',)

admin.site.register(User, UserAdmin)
admin.site.register(Journal)
admin.site.register(Article)
admin.site.register(Issue)
admin.site.register(ArticleVersion)
admin.site.register(ArticleTag)
admin.site.register(AuditLog)
admin.site.register(IntegrationSetting)