from rest_framework import serializers
from .models import User, Journal, Article, Issue, ArticleVersion, AuditLog, IntegrationSetting


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'phone', 'name', 'surname', 'role', 'language', 'orcidId', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user


class JournalSerializer(serializers.ModelSerializer):
    manager = UserSerializer(read_only=True)
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='manager',
        write_only=True
    )

    class Meta:
        model = Journal
        fields = '__all__'


class ArticleVersionSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = ArticleVersion
        fields = ['id', 'versionNumber', 'file', 'file_url', 'submittedDate', 'notes', 'submitter']

    def get_file_url(self, obj):
        request = self.context.get('request')
        if obj.file and hasattr(obj.file, 'url') and request:
            return request.build_absolute_uri(obj.file.url)
        return None


class ArticleSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    journalName = serializers.CharField(source='journal.name', read_only=True)
    versions = ArticleVersionSerializer(many=True, read_only=True)
    assignedEditorName = serializers.CharField(source='assignedEditor.get_full_name', read_only=True, default='')

    class Meta:
        model = Article
        fields = '__all__'
        read_only_fields = ['author', 'submittedDate']

    def get_fields(self):
        fields = super().get_fields()
        if self.context.get('request'):
            fields['versions'].context.update(self.context)
        return fields


class IssueSerializer(serializers.ModelSerializer):
    articles = ArticleSerializer(many=True, read_only=True)

    class Meta:
        model = Issue
        fields = '__all__'


class AuditLogSerializer(serializers.ModelSerializer):
    userEmail = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = AuditLog
        fields = '__all__'


class IntegrationSettingSerializer(serializers.ModelSerializer):
    apiKeyMasked = serializers.SerializerMethodField()

    class Meta:
        model = IntegrationSetting
        fields = ['serviceName', 'isEnabled', 'apiKeyMasked', 'monthlyLimit', 'serviceUrl']

    def get_apiKeyMasked(self, obj):
        if obj.apiKey:
            return f"********{obj.apiKey[-4:]}"
        return ""