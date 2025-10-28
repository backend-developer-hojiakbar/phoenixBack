from rest_framework import viewsets, permissions, status, generics, mixins, serializers
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
import time
from django.utils import timezone
import json
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from .models import ClickTransaction, Service, ServiceOrder

from .models import (
    User, Journal, Article, Issue, AuditLog, IntegrationSetting, JournalCategory,
    ArticleVersion, JournalType, EditorialBoardApplication, Soha
)
from .serializers import (
    UserSerializer, JournalSerializer, ArticleSerializer, IssueSerializer, AuditLogSerializer,
    IntegrationSettingSerializer, JournalCategorySerializer, JournalTypeSerializer,
    EditorialBoardApplicationSerializer, ServiceSerializer, ServiceOrderSerializer, SohaSerializer
)
from .permissions import IsAdminUser, IsJournalManager, IsClientUser, IsOwnerOrAdmin, IsAssignedEditorOrAdmin, \
    IsAccountantUser, IsWriterUser


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

        if user.role == User.Role.JOURNAL_MANAGER:
            return base_queryset.filter(
                journal__manager=user,
                submissionPaymentStatus=Article.PaymentStatus.PAYMENT_COMPLETED
            ).order_by('-submittedDate')

        if user.role in [User.Role.ADMIN, User.Role.ACCOUNTANT]:
            return base_queryset.all().order_by('-submittedDate')

        return Article.objects.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        journal = serializer.validated_data.get('journal')
        if not journal:
            raise serializers.ValidationError({"detail": "Journal is required."})

        assigned_editor = journal.manager if journal else None

        article = serializer.save(
            author=self.request.user,
            assignedEditor=assigned_editor,
            status=Article.ArticleStatus.PENDING,
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING
        )

        is_partner = 'hamkor' in self.request.user.get_full_name().lower()
        amount = journal.partner_price if is_partner else journal.regular_price

        transaction = ClickTransaction.objects.create(
            user=self.request.user,
            amount=amount,
            merchant_trans_id=f"article_{article.id}_{int(time.time())}",
            content_object=article,
        )

        payment_url = (
            f"https://my.click.uz/services/pay"
            f"?service_id={settings.CLICK_SERVICE_ID}"
            f"&merchant_id={settings.CLICK_MERCHANT_USER_ID}"
            f"&amount={float(amount)}"
            f"&transaction_param={transaction.merchant_trans_id}"
            f"&return_url=http://localhost:5173/#/payment-status"
        )

        response_serializer = self.get_serializer(article)
        response_data = response_serializer.data
        response_data['payment_url'] = payment_url

        headers = self.get_success_headers(response_data)
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)

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
        parser_classes=[JSONParser]
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

        monthly_revenue_qs = Article.objects.filter(
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_COMPLETED
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
                                                           context=request_context).data
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

        if user.role == User.Role.CLIENT:
            data = {
                'pending': Article.objects.filter(author=user, status=Article.ArticleStatus.PENDING).count(),
                'revision': Article.objects.filter(author=user, status=Article.ArticleStatus.NEEDS_REVISION).count(),
                'accepted': Article.objects.filter(author=user, status=Article.ArticleStatus.ACCEPTED).count(),
            }
        elif user.role == User.Role.JOURNAL_MANAGER:
            data = {
                'newSubmissions': Article.objects.filter(
                    journal__manager=user,
                    status=Article.ArticleStatus.REVIEWING,
                    submissionPaymentStatus=Article.PaymentStatus.PAYMENT_COMPLETED
                ).count(),
                'reviewing': Article.objects.filter(
                    journal__manager=user,
                    status=Article.ArticleStatus.REVIEWING,
                    submissionPaymentStatus=Article.PaymentStatus.PAYMENT_COMPLETED
                ).count(),
            }
        elif user.role in [User.Role.ACCOUNTANT, User.Role.ADMIN]:
            all_articles = Article.objects.all()
            data = {
                'totalUsers': User.objects.count() if user.role == User.Role.ADMIN else None,
                'totalJournals': Journal.objects.count() if user.role == User.Role.ADMIN else None,
                'totalArticles': all_articles.count(),
                'pendingAll': all_articles.filter(
                    status=Article.ArticleStatus.PENDING).count() if user.role == User.Role.ADMIN else None,
                'payments_pending_approval': 0,
                'pending_payments_list': [],
                'total_submission_fees': all_articles.aggregate(Sum('submission_fee'))['submission_fee__sum'] or 0,
                'total_publication_fees': all_articles.aggregate(Sum('publication_fee'))['publication_fee__sum'] or 0,
            }
        return Response(data)


class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.filter(is_active=True)
    serializer_class = ServiceSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'slug'

    def get_permissions(self):
        # Allow read-only access for authenticated users
        if self.action in ['list', 'retrieve']:
            permission_classes = [permissions.IsAuthenticated]
        else:
            # Require admin privileges for create, update, delete operations
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]


class ServiceOrderViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    queryset = ServiceOrder.objects.all()
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsClientUser]
    parser_classes = [MultiPartParser, FormParser]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = serializer.validated_data['service']

        # Calculate dynamic price for printed publications based on page count
        form_data_str = request.data.get('form_data_str', '{}')
        try:
            form_data = json.loads(form_data_str)
        except json.JSONDecodeError:
            form_data = {}

        if service.slug == 'printed-publications':
            # Calculate price based on pages
            book_pages = form_data.get('bookPages', 0)
            quantity = form_data.get('quantity', 1)
            try:
                book_pages = int(book_pages)
                quantity = int(quantity)
            except (ValueError, TypeError):
                book_pages = 0
                quantity = 1

            # Base price calculation: 400 UZS per page
            base_price = book_pages * 400

            # Add cover type premium
            cover_type = form_data.get('coverType', 'soft')
            if cover_type == 'hard':
                base_price += 25000  # Additional 25,000 UZS for hard cover
            elif cover_type == 'soft':
                base_price += 10000  # Additional 10,000 UZS for soft cover

            # Add ISBN price if requested
            include_isbn = form_data.get('includeISBN', False)
            if include_isbn:
                base_price += 600000  # Additional 600,000 UZS for ISBN

            # Multiply by quantity
            total_price = base_price * quantity

            # Minimum price of 4000 UZS
            if total_price < 4000:
                total_price = 4000

            service_price = total_price
        else:
            service_price = float(service.price)

        service_order = serializer.save(
            user=self.request.user,
            status=ServiceOrder.Status.PENDING_PAYMENT,
            calculated_price=service_price
        )

        transaction = ClickTransaction.objects.create(
            user=self.request.user,
            amount=service_price,
            merchant_trans_id=f"service_{service_order.id}_{int(time.time())}",
            content_object=service_order,
        )

        payment_url = (
            f"https://my.click.uz/services/pay"
            f"?service_id={settings.CLICK_SERVICE_ID}"
            f"&merchant_id={settings.CLICK_MERCHANT_USER_ID}"
            f"&amount={service_price}"
            f"&transaction_param={transaction.merchant_trans_id}"
            f"&return_url=http://localhost:5173/#/payment-status"
        )

        response_data = serializer.data
        response_data['payment_url'] = payment_url

        headers = self.get_success_headers(response_data)
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)


class WriterDashboardSummaryView(APIView):
    permission_classes = [IsWriterUser]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        data = {}
        request_context = {'request': request}

        if user.role == User.Role.WRITER:
            data = {
                'pending': Article.objects.filter(author=user, status=Article.ArticleStatus.PENDING).count(),
                'revision': Article.objects.filter(author=user, status=Article.ArticleStatus.NEEDS_REVISION).count(),
                'accepted': Article.objects.filter(author=user, status=Article.ArticleStatus.ACCEPTED).count(),
                'totalArticles': Article.objects.filter(author=user).count(),
            }
        return Response(data)


class WriterArticleViewSet(viewsets.ModelViewSet):
    serializer_class = ArticleSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsWriterUser]

    def get_serializer_context(self):
        return {'request': self.request}

    def get_queryset(self):
        user = self.request.user
        return Article.objects.select_related('author', 'journal', 'assignedEditor').prefetch_related(
            'versions').filter(author=user).order_by('-submittedDate')

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        journal = serializer.validated_data.get('journal')
        if not journal:
            raise serializers.ValidationError({"detail": "Journal is required."})

        assigned_editor = journal.manager if journal else None

        article = serializer.save(
            author=self.request.user,
            assignedEditor=assigned_editor,
            status=Article.ArticleStatus.PENDING,
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING
        )

        is_partner = 'hamkor' in self.request.user.get_full_name().lower()
        amount = journal.partner_price if is_partner else journal.regular_price

        transaction = ClickTransaction.objects.create(
            user=self.request.user,
            amount=amount,
            merchant_trans_id=f"article_{article.id}_{int(time.time())}",
            content_object=article,
        )

        payment_url = (
            f"https://my.click.uz/services/pay"
            f"?service_id={settings.CLICK_SERVICE_ID}"
            f"&merchant_id={settings.CLICK_MERCHANT_USER_ID}"
            f"&amount={float(amount)}"
            f"&transaction_param={transaction.merchant_trans_id}"
            f"&return_url=http://localhost:5173/#/payment-status"
        )

        response_serializer = self.get_serializer(article)
        response_data = response_serializer.data
        response_data['payment_url'] = payment_url

        headers = self.get_success_headers(response_data)
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)

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


class UDCAssignmentViewSet(viewsets.ModelViewSet):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsWriterUser]

    def get_queryset(self):
        # Writers can only see UDC classification orders that are pending assignment (IN_PROGRESS)
        return ServiceOrder.objects.filter(
            service__slug='udc-classification',
            status=ServiceOrder.Status.IN_PROGRESS
        ).select_related('user', 'service').order_by('-created_at')

    def get_permissions(self):
        if self.action == 'assign_udc':
            # Only writers can assign UDC codes
            permission_classes = [IsWriterUser]
        else:
            # For listing, only writers can view
            permission_classes = [IsWriterUser]
        return [permission() for permission in permission_classes]

    @action(detail=True, methods=['post'], url_path='assign-udc')
    def assign_udc(self, request, pk=None):
        order = self.get_object()
        udc_code = request.data.get('udc_code')

        if not udc_code:
            return Response({'error': 'UDC code is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Update the order with UDC code and change status
        order.udc_code = udc_code
        order.status = ServiceOrder.Status.UDC_ASSIGNED
        order.assigned_writer = request.user
        order.save()

        # Create notification or log entry if needed
        # This could be extended to send notifications to the author

        return Response(self.get_serializer(order).data)


class WriterUDCOrdersViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsWriterUser]

    def get_queryset(self):
        # Writers can see all their assigned UDC orders
        return ServiceOrder.objects.filter(
            assigned_writer=self.request.user,
            service__slug='udc-classification'
        ).select_related('user', 'service').order_by('-created_at')


class SohaViewSet(viewsets.ModelViewSet):
    queryset = Soha.objects.all().order_by('name')
    serializer_class = SohaSerializer
    permission_classes = [IsAdminUser]

    def get_permissions(self):
        # Allow read-only access for non-admin users (for dropdowns, etc.)
        if self.action == 'list' or self.action == 'retrieve':
            permission_classes = [permissions.IsAuthenticated]
        else:
            permission_classes = [IsAdminUser]
        return [permission() for permission in permission_classes]


class PrintedPublicationsViewSet(viewsets.ModelViewSet):
    serializer_class = ServiceOrderSerializer
    permission_classes = [IsWriterUser | IsAdminUser]

    def get_queryset(self):
        # Both writers and admins can see printed publications orders
        return ServiceOrder.objects.filter(
            service__slug='printed-publications'
        ).select_related('user', 'service', 'assigned_writer').order_by('-created_at')

    def get_permissions(self):
        if self.action in ['update_status', 'assign_writer']:
            # Only writers and admins can update status
            permission_classes = [IsWriterUser | IsAdminUser]
        else:
            # For listing, only writers and admins can view
            permission_classes = [IsWriterUser | IsAdminUser]
        return [permission() for permission in permission_classes]

    @action(detail=True, methods=['post'], url_path='update-status')
    def update_status(self, request, pk=None):
        order = self.get_object()
        status = request.data.get('status')
        printing_status = request.data.get('printing_status')
        tracking_number = request.data.get('tracking_number')

        if status:
            order.status = status
        if printing_status:
            order.printing_status = printing_status
        if tracking_number:
            order.tracking_number = tracking_number
            if status == ServiceOrder.Status.SHIPPED:
                order.shipped_date = timezone.now()

        order.save()
        return Response(self.get_serializer(order).data)

    @action(detail=True, methods=['post'], url_path='assign-writer')
    def assign_writer(self, request, pk=None):
        order = self.get_object()
        writer_id = request.data.get('writer_id')

        if not writer_id:
            return Response({'error': 'Writer ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            writer = User.objects.get(id=writer_id, role=User.Role.WRITER)
            order.assigned_writer = writer
            order.save()
            return Response(self.get_serializer(order).data)
        except User.DoesNotExist:
            return Response({'error': 'Writer not found.'}, status=status.HTTP_404_NOT_FOUND)
