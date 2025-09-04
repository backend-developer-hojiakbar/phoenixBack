from rest_framework import viewsets, permissions, status, generics, mixins
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Count, Sum
from django.db.models.functions import TruncMonth
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import random
import io

from .models import (
    User, Journal, Article, Issue, AuditLog, IntegrationSetting, JournalCategory,
    ArticleVersion, JournalType, EditorialBoardApplication
)
from .serializers import (
    UserSerializer, JournalSerializer, ArticleSerializer, IssueSerializer, AuditLogSerializer,
    IntegrationSettingSerializer, JournalCategorySerializer, JournalTypeSerializer,
    EditorialBoardApplicationSerializer
)
from .permissions import IsAdminUser, IsJournalManager, IsClientUser, IsOwnerOrAdmin, IsAssignedEditorOrAdmin, IsAccountantUser

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer


class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            user_data = UserSerializer(user).data
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token), 'user': user_data})
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]


class JournalTypeViewSet(viewsets.ModelViewSet):
    queryset = JournalType.objects.all()
    serializer_class = JournalTypeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticated]
        else:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()


class JournalCategoryViewSet(viewsets.ModelViewSet):
    queryset = JournalCategory.objects.all()
    serializer_class = JournalCategorySerializer
    permission_classes = [permissions.IsAuthenticated]


class JournalViewSet(viewsets.ModelViewSet):
    queryset = Journal.objects.select_related('journal_type', 'category', 'manager').all()
    serializer_class = JournalSerializer
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticated]
        else:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def get_serializer_context(self):
        return {'request': self.request}


class ArticleViewSet(viewsets.ModelViewSet):
    serializer_class = ArticleSerializer
    parser_classes = [MultiPartParser, FormParser]

    def get_serializer_context(self):
        return {'request': self.request}

    def get_permissions(self):
        if self.action in ['request_revision', 'reject_article', 'accept_article', 'add_link_or_attachment']:
            self.permission_classes = [IsAdminUser | IsJournalManager]
        elif self.action == 'submit_revision':
            self.permission_classes = [IsClientUser, IsOwnerOrAdmin]
        elif self.action == 'create':
            self.permission_classes = [IsClientUser]
        else:
            self.permission_classes = [permissions.IsAuthenticated]
        return super().get_permissions()

    def get_queryset(self):
        user = self.request.user
        base_queryset = Article.objects.select_related('author', 'journal', 'assignedEditor').prefetch_related(
            'versions')
        if user.role == User.Role.CLIENT:
            return base_queryset.filter(author=user).order_by('-submittedDate')
        elif user.role == User.Role.JOURNAL_MANAGER:
            return base_queryset.filter(journal__manager=user,
                                        submissionPaymentStatus=Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING).order_by(
                '-submittedDate')
        elif user.role in [User.Role.ADMIN, User.Role.ACCOUNTANT]:
            return base_queryset.all().order_by('-submittedDate')
        return Article.objects.none()

    def perform_create(self, serializer):
        plagiarism_percentage = random.uniform(5.0, 25.0)
        journal = serializer.validated_data.get('journal')
        assigned_editor = journal.manager if journal else None
        serializer.save(
            author=self.request.user,
            assignedEditor=assigned_editor,
            plagiarism_percentage=plagiarism_percentage,
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL
        )

    @action(detail=True, methods=['post'], url_path='request_revision')
    def request_revision(self, request, pk=None):
        article = self.get_object()
        notes = request.data.get('notes', '')
        article.status = Article.ArticleStatus.NEEDS_REVISION
        article.managerNotes = notes
        article.save()
        return Response(self.get_serializer(article).data)

    @action(detail=True, methods=['post'], url_path='reject_article')
    def reject_article(self, request, pk=None):
        article = self.get_object()
        notes = request.data.get('notes', '')
        article.status = Article.ArticleStatus.REJECTED
        article.managerNotes = notes
        article.save()
        return Response(self.get_serializer(article).data)

    @action(detail=True, methods=['post'], url_path='accept_article', parser_classes=[MultiPartParser, FormParser])
    def accept_article(self, request, pk=None):
        article = self.get_object()
        article.status = Article.ArticleStatus.ACCEPTED

        final_file = request.data.get('finalVersionFile')
        if final_file:
            article.finalVersionFile = final_file

        if article.finalVersionFile:
            # Bu yerda sertifikat generatsiya qilish logikasi bo'lishi kerak.
            # Hozircha test uchun yakuniy faylni sertifikat sifatida ishlatamiz.
            article.certificate_file = article.finalVersionFile

        article.save()
        return Response(self.get_serializer(article).data)

    @action(detail=True, methods=['post'], url_path='submit-revision', parser_classes=[MultiPartParser, FormParser])
    def submit_revision(self, request, pk=None):
        article = self.get_object()
        if article.author != request.user:
            return Response({'error': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
        new_file = request.data.get('file')
        if not new_file:
            return Response({'error': 'A new file is required.'}, status=status.HTTP_400_BAD_REQUEST)
        ArticleVersion.objects.create(article=article, versionNumber=article.versions.count() + 1, file=new_file,
                                      submitter=request.user)
        article.status = Article.ArticleStatus.REVIEWING
        article.plagiarism_percentage = random.uniform(2.0, 15.0)
        article.save()
        return Response(self.get_serializer(article).data)

    @action(detail=True, methods=['patch'], url_path='add-link-or-attachment',
            parser_classes=[MultiPartParser, FormParser])
    def add_link_or_attachment(self, request, pk=None):
        article = self.get_object()
        serializer = self.get_serializer(article, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class EditorialBoardApplicationViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet
):
    queryset = EditorialBoardApplication.objects.select_related('user').all().order_by('-submitted_at')
    serializer_class = EditorialBoardApplicationSerializer
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.action == 'create':
            self.permission_classes = [IsClientUser]
        else:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(
        detail=True,
        methods=['patch'],
        url_path='update-status',
        parser_classes=[JSONParser]  # To'g'ri joydan import qilingan
    )
    def update_status(self, request, pk=None):
        application = self.get_object()
        new_status = request.data.get('status')

        if new_status not in [choice[0] for choice in EditorialBoardApplication.ApplicationStatus.choices]:
            return Response({'error': 'Invalid status value.'}, status=status.HTTP_400_BAD_REQUEST)

        application.status = new_status
        application.save(update_fields=['status'])

        if new_status == EditorialBoardApplication.ApplicationStatus.APPROVED:
            user = application.user
            user.role = User.Role.JOURNAL_MANAGER
            user.save(update_fields=['role'])

        return Response(self.get_serializer(application).data)


class FinancialReportAPIView(APIView):
    permission_classes = [IsAdminUser | IsAccountantUser]

    def get(self, request, *args, **kwargs):
        export_format = request.query_params.get('format')

        pending_payment_articles_qs = Article.objects.filter(
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL
        ).select_related('author').order_by('submittedDate')

        monthly_revenue_qs = Article.objects.filter(
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING
        ).annotate(month=TruncMonth('submittedDate')).values('month').annotate(total=Sum('submission_fee')).order_by(
            'month')

        approved_articles_qs = Article.objects.filter(
            status=Article.ArticleStatus.ACCEPTED
        ).select_related('author', 'journal').order_by('-publicationDate')

        if export_format == 'excel':
            return self.export_to_excel(monthly_revenue_qs, approved_articles_qs)
        if export_format == 'pdf':
            return self.export_to_pdf(monthly_revenue_qs, approved_articles_qs)

        request_context = {'request': request}
        data = {
            'monthly_revenue': list(monthly_revenue_qs),
            'approved_articles_history': ArticleSerializer(approved_articles_qs, many=True,
                                                           context=request_context).data,
            'pending_payments_list': ArticleSerializer(pending_payment_articles_qs, many=True,
                                                       context=request_context).data,
        }
        return Response(data)

    def export_to_excel(self, monthly_revenue, approved_articles):
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="financial_report.xlsx"'
        wb = Workbook()
        ws1 = wb.active
        ws1.title = "Oylik Daromad"
        ws1.append(['Oy', 'Jami Daromad (UZS)'])
        for item in monthly_revenue:
            ws1.append([item['month'].strftime('%Y-%m'), item['total']])
        ws2 = wb.create_sheet(title="Tasdiqlangan Maqolalar")
        ws2.append(['ID', 'Sarlavha', 'Muallif', 'Jurnal', 'Tasdiqlangan Sana'])
        for article in approved_articles:
            ws2.append([
                article.id,
                article.title,
                article.author.get_full_name(),
                article.journal.name if article.journal else 'N/A',
                article.publicationDate.strftime('%Y-%m-%d') if article.publicationDate else 'N/A'
            ])
        wb.save(response)
        return response

    def export_to_pdf(self, monthly_revenue, approved_articles):
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        y_position = height - inch
        p.drawString(inch, y_position, "Moliyaviy Hisobot")
        y_position -= 0.5 * inch
        p.drawString(inch, y_position, "Oylik Daromad")
        y_position -= 0.25 * inch
        for item in monthly_revenue:
            p.drawString(inch, y_position, f"{item['month'].strftime('%Y-%m')}: {item['total']} UZS")
            y_position -= 0.25 * inch
            if y_position < inch:
                p.showPage()
                y_position = height - inch
        y_position -= 0.5 * inch
        p.drawString(inch, y_position, "Tasdiqlangan Maqolalar Tarixi")
        y_position -= 0.25 * inch
        for article in approved_articles:
            line = f"ID {article.id}: {article.title[:40]}... ({article.author.get_full_name()})"
            p.drawString(inch, y_position, line)
            y_position -= 0.25 * inch
            if y_position < inch:
                p.showPage()
                y_position = height - inch
        p.save()
        buffer.seek(0)
        return HttpResponse(buffer, content_type='application/pdf')


class ApprovePaymentAPIView(APIView):
    permission_classes = [IsAdminUser | IsAccountantUser]

    def post(self, request, article_id, *args, **kwargs):
        article = get_object_or_404(Article.objects.select_related('author', 'journal'), id=article_id)
        author = article.author
        journal = article.journal

        if not journal:
            return Response({'error': 'Article is not associated with a journal.'}, status=status.HTTP_400_BAD_REQUEST)

        # Hamkorlikni tekshirish
        is_partner = 'hamkor' in author.name.lower() or 'xamkor' in author.name.lower() or \
                     'hamkor' in author.surname.lower() or 'xamkor' in author.surname.lower()

        # Narxni avtomatik belgilash
        submission_fee = journal.partner_price if is_partner else journal.regular_price

        article.submission_fee = submission_fee
        article.submissionPaymentStatus = Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING
        article.status = Article.ArticleStatus.REVIEWING
        article.save()
        return Response(ArticleSerializer(article, context={'request': request}).data)


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class SystemSettingsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, *args, **kwargs):
        settings = IntegrationSetting.objects.all()
        serializer = IntegrationSettingSerializer(settings, many=True)
        return Response(serializer.data)

    def patch(self, request, service_name, *args, **kwargs):
        setting = get_object_or_404(IntegrationSetting, serviceName=service_name)
        serializer = IntegrationSettingSerializer(setting, data=request.data, partial=True)
        if serializer.is_valid():
            api_key = request.data.get('apiKey')
            if api_key:
                setting.apiKey = api_key
            serializer.save()
            setting.save(update_fields=['apiKey'] if api_key else None)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IssueViewSet(viewsets.ModelViewSet):
    queryset = Issue.objects.all()
    serializer_class = IssueSerializer
    permission_classes = [IsAdminUser | IsJournalManager]

    def get_queryset(self):
        user = self.request.user
        if user.role == User.Role.JOURNAL_MANAGER:
            return Issue.objects.filter(journal__manager=user)
        return super().get_queryset()


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all().order_by('-timestamp')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]


class DashboardSummaryView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        data = {}
        request_context = {'request': request}

        # Bu yerda UserRole o'rniga User.Role ishlatildi
        if user.role == User.Role.CLIENT:
            data = {
                'pending': Article.objects.filter(author=user, status=Article.ArticleStatus.PENDING).count(),
                'revision': Article.objects.filter(author=user, status=Article.ArticleStatus.NEEDS_REVISION).count(),
                'accepted': Article.objects.filter(author=user, status=Article.ArticleStatus.ACCEPTED).count(),
            }
        elif user.role == User.Role.JOURNAL_MANAGER:
            data = {
                'newSubmissions': Article.objects.filter(journal__manager=user,
                                                         status=Article.ArticleStatus.REVIEWING).count(),
                'reviewing': Article.objects.filter(journal__manager=user,
                                                    status=Article.ArticleStatus.REVIEWING).count(),
            }
        # Bu yerda UserRole o'rniga User.Role ishlatildi
        elif user.role in [User.Role.ACCOUNTANT, User.Role.ADMIN]:
            pending_payment_articles = Article.objects.filter(
                submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL
            ).select_related('author').order_by('submittedDate')

            data = {
                'totalUsers': User.objects.count() if user.role == User.Role.ADMIN else None,
                'totalJournals': Journal.objects.count() if user.role == User.Role.ADMIN else None,
                'totalArticles': Article.objects.count(),
                'pendingAll': Article.objects.filter(
                    status=Article.ArticleStatus.PENDING).count() if user.role == User.Role.ADMIN else None,
                'payments_pending_approval': pending_payment_articles.count(),
                'pending_payments_list': ArticleSerializer(pending_payment_articles, many=True,
                                                           context=request_context).data,
                'total_submission_fees': Article.objects.aggregate(Sum('submission_fee'))['submission_fee__sum'] or 0,
                'total_publication_fees': Article.objects.aggregate(Sum('publication_fee'))[
                                              'publication_fee__sum'] or 0,
            }
        return Response(data)