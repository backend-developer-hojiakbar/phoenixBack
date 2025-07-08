from rest_framework import serializers
from .models import User, Journal, Article, Issue, ArticleVersion, AuditLog, IntegrationSetting, JournalCategory

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'phone', 'name', 'surname', 'role', 'language', 'orcidId', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user

class JournalCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = JournalCategory
        fields = '__all__'

class JournalSerializer(serializers.ModelSerializer):
    manager = UserSerializer(read_only=True)
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='manager',
        write_only=True
    )
    category = JournalCategorySerializer(read_only=True)
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=JournalCategory.objects.all(),
        source='category',
        write_only=True,
        allow_null=True
    )

    class Meta:
        model = Journal
        fields = '__all__'


# serializers.py
class ArticleVersionSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = ArticleVersion
        fields = ['id', 'versionNumber', 'file', 'file_url', 'submittedDate', 'notes', 'submitter']

    def get_file_url(self, obj):
        request = self.context.get('request')  # <--- MUAMMO MANA SHU YERDA
        if obj.file and hasattr(obj.file, 'url') and request:
            return request.build_absolute_uri(obj.file.url)
        return None


class ArticleSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    journalName = serializers.CharField(source='journal.name', read_only=True)
    versions = ArticleVersionSerializer(many=True, read_only=True)
    assignedEditorName = serializers.CharField(source='assignedEditor.get_full_name', read_only=True, default='')
    submissionReceiptFileUrl = serializers.FileField(source='submissionReceiptFile', read_only=True)
    finalVersionFileUrl = serializers.FileField(source='finalVersionFile', read_only=True)
    class Meta:
        model = Article
        fields = [
            'id', 'title', 'author', 'category', 'journal', 'journalName', 'submittedDate',
            'status', 'viewCount', 'downloadCount', 'citationCount', 'publicationDate',
            'submissionTargetDetails', 'title_en', 'abstract_en', 'keywords_en',
            'assignedEditor', 'assignedEditorName', 'issue', 'submissionPaymentStatus',
            'submissionReceiptFile', 'submissionReceiptFileUrl',
            'versions',
            'managerNotes', 'finalVersionFile', 'finalVersionFileUrl',
            'submission_fee', 'publication_fee'
        ]
        read_only_fields = ['author', 'submittedDate', 'assignedEditor', 'status', 'submissionPaymentStatus']
    def get_fields(self):
        fields = super().get_fields()
        if 'request' in self.context and self.context.get('request'):
            fields['versions'].context.update(self.context)
        return fields

class IssueSerializer(serializers.ModelSerializer):
    articles = ArticleSerializer(many=True, read_only=True)
    class Meta:
        model = Issue
        fields = '__all__'

class AuditLogSerializer(serializers.ModelSerializer):
    user_phone = serializers.CharField(source='user.phone', read_only=True, allow_null=True)
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'user_phone', 'actionType', 'timestamp', 'details', 'targetEntityType', 'targetEntityId']

class IntegrationSettingSerializer(serializers.ModelSerializer):
    apiKeyMasked = serializers.SerializerMethodField()
    class Meta:
        model = IntegrationSetting
        fields = ['id', 'serviceName', 'isEnabled', 'apiKeyMasked', 'monthlyLimit', 'serviceUrl']
        read_only_fields = ['id', 'serviceName', 'apiKeyMasked']
    def get_apiKeyMasked(self, obj):
        if obj.apiKey:
            return f"********{obj.apiKey[-4:]}"
        return ""