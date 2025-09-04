from rest_framework import serializers
from .models import (
    User, Journal, Article, Issue, ArticleVersion, AuditLog, IntegrationSetting,
    JournalCategory, JournalType, EditorialBoardApplication
)


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


class JournalTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = JournalType
        fields = '__all__'


class JournalCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = JournalCategory
        fields = '__all__'


# ... api/serializers.py faylingizning boshqa qismlari

class JournalSerializer(serializers.ModelSerializer):
    manager = UserSerializer(read_only=True)
    category = JournalCategorySerializer(read_only=True)
    journal_type = JournalTypeSerializer(read_only=True)
    image_url = serializers.ImageField(source='image', use_url=True, read_only=True)

    # "required=False" va "allow_null=True" qo'shildi
    manager_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(role=User.Role.JOURNAL_MANAGER),
        source='manager', write_only=True, required=False, allow_null=True
    )
    category_id = serializers.PrimaryKeyRelatedField(
        queryset=JournalCategory.objects.all(),
        source='category', write_only=True, allow_null=True, required=False
    )
    # Bu maydon majburiy bo'lib qoladi
    journal_type_id = serializers.PrimaryKeyRelatedField(
        queryset=JournalType.objects.all(),
        source='journal_type', write_only=True
    )

    class Meta:
        model = Journal
        fields = [
            'id', 'name', 'description', 'manager', 'category', 'journal_type', 'image_url',
            'partner_price', 'regular_price', 'manager_id', 'category_id', 'journal_type_id', 'image'
        ]
        extra_kwargs = {
            'image': {'write_only': True, 'required': False}
        }


# ... api/serializers.py faylingizning qolgan qismlari


class ArticleVersionSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    def get_file_url(self, obj):
        request = self.context.get('request')
        if obj.file and hasattr(obj.file, 'url'):
            return request.build_absolute_uri(obj.file.url)
        return None

    class Meta:
        model = ArticleVersion
        fields = ['id', 'versionNumber', 'file_url', 'submittedDate', 'notes']


class ArticleSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)
    journalName = serializers.CharField(source='journal.name', read_only=True, allow_null=True)
    versions = ArticleVersionSerializer(many=True, read_only=True)
    assignedEditorName = serializers.CharField(source='assignedEditor.get_full_name', read_only=True, allow_null=True,
                                               default='')
    submissionReceiptFileUrl = serializers.SerializerMethodField()
    finalVersionFileUrl = serializers.SerializerMethodField()
    certificate_file_url = serializers.SerializerMethodField()
    attachment_file_url = serializers.SerializerMethodField()

    def get_submissionReceiptFileUrl(self, obj):
        request = self.context.get('request')
        if obj.submissionReceiptFile and hasattr(obj.submissionReceiptFile, 'url'):
            return request.build_absolute_uri(obj.submissionReceiptFile.url)
        return None

    def get_finalVersionFileUrl(self, obj):
        request = self.context.get('request')
        if obj.finalVersionFile and hasattr(obj.finalVersionFile, 'url'):
            return request.build_absolute_uri(obj.finalVersionFile.url)
        return None

    def get_certificate_file_url(self, obj):
        request = self.context.get('request')
        if obj.certificate_file and hasattr(obj.certificate_file, 'url'):
            return request.build_absolute_uri(obj.certificate_file.url)
        return None

    def get_attachment_file_url(self, obj):
        request = self.context.get('request')
        if obj.attachment_file and hasattr(obj.attachment_file, 'url'):
            return request.build_absolute_uri(obj.attachment_file.url)
        return None

    class Meta:
        model = Article
        fields = [
            'id', 'title', 'author', 'category', 'journal', 'journalName', 'submittedDate', 'status',
            'abstract_en', 'keywords_en', 'assignedEditor', 'assignedEditorName', 'submissionPaymentStatus',
            'submissionReceiptFileUrl', 'versions', 'managerNotes', 'finalVersionFileUrl', 'submission_fee',
            'plagiarism_percentage', 'certificate_file_url', 'external_link', 'attachment_file_url'
        ]


class IssueSerializer(serializers.ModelSerializer):
    articles = ArticleSerializer(many=True, read_only=True)

    class Meta:
        model = Issue
        fields = '__all__'


class AuditLogSerializer(serializers.ModelSerializer):
    user_phone = serializers.CharField(source='user.phone', read_only=True, allow_null=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'user_phone', 'actionType', 'timestamp', 'details', 'targetEntityType',
                  'targetEntityId']


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


class EditorialBoardApplicationSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    passport_file_url = serializers.SerializerMethodField()
    photo_3x4_url = serializers.SerializerMethodField()
    diploma_file_url = serializers.SerializerMethodField()

    def get_passport_file_url(self, obj):
        request = self.context.get('request')
        if obj.passport_file and hasattr(obj.passport_file, 'url'):
            return request.build_absolute_uri(obj.passport_file.url)
        return None

    def get_photo_3x4_url(self, obj):
        request = self.context.get('request')
        if obj.photo_3x4 and hasattr(obj.photo_3x4, 'url'):
            return request.build_absolute_uri(obj.photo_3x4.url)
        return None

    def get_diploma_file_url(self, obj):
        request = self.context.get('request')
        if obj.diploma_file and hasattr(obj.diploma_file, 'url'):
            return request.build_absolute_uri(obj.diploma_file.url)
        return None

    class Meta:
        model = EditorialBoardApplication
        fields = '__all__'
        read_only_fields = ['user', 'submitted_at']