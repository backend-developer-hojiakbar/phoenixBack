from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def create_user(self, phone, name, surname, password=None, **extra_fields):
        if not phone:
            raise ValueError(_('The Phone number must be set'))
        if not name:
            raise ValueError(_('The Name must be set'))
        if not surname:
            raise ValueError(_('The Surname must be set'))

        user = self.model(phone=phone, name=name, surname=surname, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, name, surname, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(phone, name, surname, password, **extra_fields)


class User(AbstractUser):
    class Role(models.TextChoices):
        CLIENT = 'client', _('Client')
        JOURNAL_MANAGER = 'journal_manager', _('Journal Manager')
        ACCOUNTANT = 'accountant', _('Accountant')
        ADMIN = 'admin', _('Admin')

    class Language(models.TextChoices):
        UZ = 'uz', _('Uzbek')
        RU = 'ru', _('Russian')
        EN = 'en', _('English')

    username = None
    phone = models.CharField(_('phone number'), max_length=20, unique=True)
    name = models.CharField(_('first name'), max_length=150)
    surname = models.CharField(_('last name'), max_length=150)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.CLIENT)
    language = models.CharField(max_length=2, choices=Language.choices, default=Language.EN)
    orcidId = models.CharField(max_length=50, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['name', 'surname']

    def __str__(self):
        return self.phone

    def get_full_name(self):
        return f"{self.name} {self.surname}".strip()

class JournalCategory(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name

class Journal(models.Model):
    class JournalType(models.TextChoices):
        INTERNATIONAL = 'international', _('International')
        LOCAL = 'local', _('Local')

    journal_type = models.CharField(max_length=20, choices=JournalType.choices, default=JournalType.LOCAL)
    name = models.CharField(max_length=255)
    name_uz = models.CharField(max_length=255, blank=True, null=True)
    name_ru = models.CharField(max_length=255, blank=True, null=True)
    name_en = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField()
    description_en = models.TextField(blank=True, null=True)
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='managed_journals')
    rulesFilePath = models.FileField(upload_to='journal_rules/', blank=True, null=True)
    templateFilePath = models.FileField(upload_to='journal_templates/', blank=True, null=True)
    issn = models.CharField(max_length=20, blank=True, null=True)
    publisher = models.CharField(max_length=100, blank=True, null=True)
    submissionChecklistText = models.TextField(blank=True, null=True)
    category = models.ForeignKey(JournalCategory, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name


class Issue(models.Model):
    journal = models.ForeignKey(Journal, on_delete=models.CASCADE, related_name='issues')
    issueNumber = models.CharField(max_length=100)
    publicationDate = models.DateField()
    coverImageUrl = models.URLField(blank=True, null=True)
    compiledIssuePath = models.FileField(upload_to='issues/', blank=True, null=True)
    isPublished = models.BooleanField(default=False)
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.journal.name} - {self.issueNumber}"


class ArticleTag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Article(models.Model):
    class ArticleStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        REVIEWING = 'reviewing', _('Reviewing')
        NEEDS_REVISION = 'needs_revision', _('Needs Revision')
        ACCEPTED = 'accepted', _('Accepted')
        REJECTED = 'rejected', _('Rejected')
        PUBLISHED = 'published', _('Published')

    class PaymentStatus(models.TextChoices):
        PAYMENT_PENDING_USER_ACTION = 'payment_pending_user_action', _('Payment Pending User Action')
        PAYMENT_PENDING_ADMIN_APPROVAL = 'payment_pending_admin_approval', _('Payment Pending Admin Approval')
        PAYMENT_APPROVED_PROCESSING = 'payment_approved_processing', _('Payment Approved Processing')
        RESULTS_READY = 'results_ready', _('Results Ready')

    title = models.CharField(max_length=255)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='articles')
    category = models.CharField(max_length=20)
    journal = models.ForeignKey(Journal, on_delete=models.SET_NULL, null=True, blank=True, related_name='articles')
    submittedDate = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=ArticleStatus.choices, default=ArticleStatus.PENDING)
    viewCount = models.PositiveIntegerField(default=0)
    downloadCount = models.PositiveIntegerField(default=0)
    citationCount = models.PositiveIntegerField(default=0)
    publicationDate = models.DateField(blank=True, null=True)
    submissionTargetDetails = models.CharField(max_length=255, blank=True, null=True)
    title_en = models.CharField(max_length=255, blank=True, null=True)
    abstract_en = models.TextField(blank=True, null=True)
    keywords_en = models.CharField(max_length=500, blank=True, null=True)
    assignedEditor = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True, related_name='assigned_articles')
    issue = models.ForeignKey(Issue, on_delete=models.SET_NULL, blank=True, null=True, related_name='articles')
    submissionPaymentStatus = models.CharField(max_length=50, choices=PaymentStatus.choices, default=PaymentStatus.PAYMENT_PENDING_USER_ACTION)
    submissionReceiptFile = models.FileField(upload_to='receipts/submission/', blank=True, null=True)
    managerNotes = models.TextField(blank=True, null=True)
    finalVersionFile = models.FileField(upload_to='article_final_versions/', blank=True, null=True)
    submission_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    publication_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return self.title


class ArticleVersion(models.Model):
    article = models.ForeignKey(Article, on_delete=models.CASCADE, related_name='versions')
    versionNumber = models.PositiveIntegerField()
    file = models.FileField(upload_to='article_versions/')
    submittedDate = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)
    submitter = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-versionNumber']

    def __str__(self):
        return f"{self.article.title} - v{self.versionNumber}"


class AuditLog(models.Model):
    class AuditActionType(models.TextChoices):
        USER_LOGIN = 'USER_LOGIN', _('User Login')
        USER_CREATED = 'USER_CREATED', _('User Created')
        USER_UPDATED = 'USER_UPDATED', _('User Updated')
        USER_DELETED = 'USER_DELETED', _('User Deleted')
        ARTICLE_SUBMITTED = 'ARTICLE_SUBMITTED', _('Article Submitted')
        ARTICLE_STATUS_CHANGED = 'ARTICLE_STATUS_CHANGED', _('Article Status Changed')
        PAYMENT_APPROVED = 'PAYMENT_APPROVED', _('Payment Approved')

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    actionType = models.CharField(max_length=50, choices=AuditActionType.choices)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict)
    targetEntityType = models.CharField(max_length=50, blank=True, null=True)
    targetEntityId = models.PositiveIntegerField(blank=True, null=True)

    def __str__(self):
        return f"{self.actionType} by {self.user} at {self.timestamp}"


class IntegrationSetting(models.Model):
    class ServiceName(models.TextChoices):
        AI_GEMINI = 'AI_Gemini', _('AI Gemini')
        PLAGIARISM_CHECKER = 'PlagiarismChecker', _('Plagiarism Checker')
        DOI_PROVIDER = 'DOI_Provider', _('DOI Provider')

    serviceName = models.CharField(max_length=50, choices=ServiceName.choices, unique=True)
    isEnabled = models.BooleanField(default=False)
    apiKey = models.CharField(max_length=255, blank=True)
    monthlyLimit = models.PositiveIntegerField(blank=True, null=True)
    serviceUrl = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.get_serviceName_display()