from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Count, Sum
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from .models import User, Journal, Article, Issue, AuditLog, IntegrationSetting, JournalCategory,ArticleVersion
from .serializers import (
    UserSerializer, JournalSerializer, ArticleSerializer,
    IssueSerializer, AuditLogSerializer, IntegrationSettingSerializer, JournalCategorySerializer
)
from .permissions import IsAdminUser, IsJournalManager, IsClientUser, IsOwnerOrAdmin, IsAssignedEditorOrAdmin, \
    IsAccountantUser


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
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': user_data,
            })
        return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class AdminPaymentApprovalView(APIView):
    # Ruxsatlarni o'zgartiramiz, chunki narx belgilash uchun Admin yoki Buxgalter kerak
    permission_classes = [IsAdminUser | IsAccountantUser]

    def post(self, request, article_id, *args, **kwargs):
        article = get_object_or_404(Article, id=article_id)

        # Frontend'dan keladigan 'submission_fee'ni olamiz
        submission_fee = request.data.get('submission_fee')

        if submission_fee is None:
            return Response(
                {'error': 'Submission fee is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Narxni saqlaymiz
            article.submission_fee = submission_fee
            # Maqola holatini va to'lov statusini o'zgartiramiz
            article.submissionPaymentStatus = Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING
            article.status = Article.ArticleStatus.REVIEWING
            article.save()

            serializer = ArticleSerializer(article, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class JournalTypesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        types = [{'value': choice[0], 'label': str(choice[1])} for choice in Journal.JournalType.choices]
        return Response(types)


class JournalCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = JournalCategory.objects.all().order_by('name')
    serializer_class = JournalCategorySerializer
    permission_classes = [IsAuthenticated]


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]


class JournalViewSet(viewsets.ModelViewSet):
    serializer_class = JournalSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticated]
        else:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    def get_queryset(self):
        user = self.request.user
        if user.role == User.Role.JOURNAL_MANAGER:
            queryset = Journal.objects.filter(manager=user)
        else:
            queryset = Journal.objects.all()

        journal_type = self.request.query_params.get('journal_type')
        category_id = self.request.query_params.get('category')

        if journal_type:
            queryset = queryset.filter(journal_type=journal_type)
        if category_id:
            queryset = queryset.filter(category__id=category_id)

        return queryset

    def get_serializer_context(self):
        return {'request': self.request}


class ArticleViewSet(viewsets.ModelViewSet):
    serializer_class = ArticleSerializer
    parser_classes = [MultiPartParser, FormParser]

    def get_serializer_context(self):
        return {'request': self.request}

    def get_permissions(self):
        # Bu action'larni to'g'ri ro'yxatga kiritamiz
        if self.action in ['request_revision', 'reject_article', 'accept_article']:
            self.permission_classes = [IsJournalManager | IsAssignedEditorOrAdmin]
        # submit_revision endi alohida permission_classes bilan ishlaydi
        elif self.action == 'submit_revision':
            self.permission_classes = [IsClientUser, IsOwnerOrAdmin]
        elif self.action == 'create':
            self.permission_classes = [IsClientUser]
        elif self.action in ['update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAdminUser]
        else:
            self.permission_classes = [permissions.IsAuthenticated]
        return super().get_permissions()

    def get_queryset(self):
        user = self.request.user
        base_queryset = Article.objects.select_related(
            'author', 'journal', 'assignedEditor', 'issue'
        ).prefetch_related('versions')

        if user.role == User.Role.CLIENT:
            return base_queryset.filter(author=user).order_by('-submittedDate')
        elif user.role == User.Role.JOURNAL_MANAGER:
            return base_queryset.filter(
                assignedEditor=user,
                submissionPaymentStatus=Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING
            ).order_by('-submittedDate')
        elif user.role in [User.Role.ADMIN, User.Role.ACCOUNTANT]:
            return base_queryset.all().order_by('-submittedDate')
        return Article.objects.none()

    # ... perform_create va boshqa action'lar o'zgarishsiz ...
    def perform_create(self, serializer):
        journal = serializer.validated_data.get('journal')
        assigned_editor = None
        if journal and journal.manager:
            assigned_editor = journal.manager
        serializer.save(
            author=self.request.user,
            assignedEditor=assigned_editor,
            submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL
        )

    # ... request_revision, reject, accept action'lari avvalgidek qoladi ...
    @action(detail=True, methods=['post'], url_path='request-revision')
    def request_revision(self, request, pk=None):
        article = self.get_object()
        notes = request.data.get('notes', '')
        if not notes:
            return Response({'error': 'Notes for revision are required.'}, status=status.HTTP_400_BAD_REQUEST)
        article.status = Article.ArticleStatus.NEEDS_REVISION
        article.managerNotes = notes
        article.save()
        serializer = self.get_serializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='reject')
    def reject_article(self, request, pk=None):
        article = self.get_object()
        notes = request.data.get('notes', '')
        article.status = Article.ArticleStatus.REJECTED
        article.managerNotes = notes
        article.save()
        serializer = self.get_serializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='accept', parser_classes=[MultiPartParser, FormParser])
    def accept_article(self, request, pk=None):
        article = self.get_object()
        final_file = request.data.get('finalVersionFile')
        if not final_file:
            return Response({'error': 'Final version file is required for acceptance.'},
                            status=status.HTTP_400_BAD_REQUEST)
        article.status = Article.ArticleStatus.ACCEPTED
        article.finalVersionFile = final_file
        article.managerNotes = "Maqola qabul qilindi. Yakuniy versiya yuklandi."
        article.save()
        serializer = self.get_serializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # BU ACTION'NI YANGILAYMIZ
    @action(detail=True, methods=['post'], url_path='submit-revision', parser_classes=[MultiPartParser, FormParser])
    def submit_revision(self, request, pk=None):
        article = self.get_object()

        # Bu tekshiruv IsOwnerOrAdmin permission'ida qilinadi, lekin qo'shimcha tekshirish zarar qilmaydi.
        if article.author != request.user:
            return Response({'error': 'You do not have permission to perform this action.'},
                            status=status.HTTP_403_FORBIDDEN)

        if article.status not in [Article.ArticleStatus.NEEDS_REVISION, Article.ArticleStatus.REJECTED]:
            return Response(
                {'error': 'You can only submit revisions for articles that need revision or were rejected.'},
                status=status.HTTP_400_BAD_REQUEST)

        new_file = request.data.get('file')
        notes = request.data.get('notes', '')

        if not new_file:
            return Response({'error': 'A new file for the revision is required.'}, status=status.HTTP_400_BAD_REQUEST)

        last_version_number = article.versions.count()
        ArticleVersion.objects.create(
            article=article,
            versionNumber=last_version_number + 1,
            file=new_file,
            notes=notes,
            submitter=request.user
        )

        article.status = Article.ArticleStatus.REVIEWING
        article.managerNotes = "Muallif tomonidan yangi versiya yuborildi."
        article.save()

        serializer = self.get_serializer(article)
        return Response(serializer.data, status=status.HTTP_200_OK)


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


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        data = {}
        if user.role == User.Role.CLIENT:
            data = {
                'pending': Article.objects.filter(author=user, status=Article.ArticleStatus.PENDING).count(),
                'revision': Article.objects.filter(author=user, status=Article.ArticleStatus.NEEDS_REVISION).count(),
                'accepted': Article.objects.filter(author=user, status=Article.ArticleStatus.ACCEPTED).count(),
            }
        elif user.role == User.Role.JOURNAL_MANAGER:
            data = {
                'newSubmissions': Article.objects.filter(assignedEditor=user,
                                                         status=Article.ArticleStatus.REVIEWING).count(),
                'reviewing': Article.objects.filter(assignedEditor=user,
                                                    status=Article.ArticleStatus.REVIEWING).count(),
            }
        elif user.role == User.Role.ACCOUNTANT:
            data = {
                'total_articles': Article.objects.count(),
                'payments_pending_approval': Article.objects.filter(
                    submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL).count(),
                'total_submission_fees': Article.objects.aggregate(Sum('submission_fee'))['submission_fee__sum'] or 0,
                'total_publication_fees': Article.objects.aggregate(Sum('publication_fee'))[
                                              'publication_fee__sum'] or 0,
            }
        elif user.role == User.Role.ADMIN:
            data = {
                'totalUsers': User.objects.count(),
                'totalJournals': Journal.objects.count(),
                'totalArticles': Article.objects.count(),
                'pendingAll': Article.objects.filter(status=Article.ArticleStatus.PENDING).count(),
            }
        return Response(data)


class FinancialReportsView(APIView):
    permission_classes = [IsAdminUser | IsAccountantUser]

    def get(self, request, *args, **kwargs):
        total_revenue = (Article.objects.aggregate(Sum('submission_fee'))['submission_fee__sum'] or 0) + \
                        (Article.objects.aggregate(Sum('publication_fee'))['publication_fee__sum'] or 0)

        articles_by_status = Article.objects.values('status').annotate(count=Count('id'))
        payments_by_status = Article.objects.values('submissionPaymentStatus').annotate(count=Count('id'))

        report_data = {
            'total_revenue': total_revenue,
            'articles_by_status': list(articles_by_status),
            'payments_by_status': list(payments_by_status),
            'payments_pending_approval_list': ArticleSerializer(
                Article.objects.filter(submissionPaymentStatus=Article.PaymentStatus.PAYMENT_PENDING_ADMIN_APPROVAL),
                many=True,
                context={'request': request}  # <--- MANA SHU CONTEXT'NI QO'SHING
            ).data
        }
        return Response(report_data)


class SystemSettingsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, *args, **kwargs):
        for service_name, _ in IntegrationSetting.ServiceName.choices:
            IntegrationSetting.objects.get_or_create(serviceName=service_name)
        settings = IntegrationSetting.objects.all()
        serializer = IntegrationSettingSerializer(settings, many=True)
        return Response(serializer.data)


class SystemSettingsDetailView(APIView):
    permission_classes = [IsAdminUser]

    def get_object(self, service_name):
        try:
            return IntegrationSetting.objects.get(serviceName=service_name)
        except IntegrationSetting.DoesNotExist:
            return None

    def patch(self, request, service_name, *args, **kwargs):
        setting = self.get_object(service_name)
        if not setting:
            return Response({'error': 'Setting not found'}, status=status.HTTP_404_NOT_FOUND)
        data = request.data.copy()
        data.pop('apiKeyMasked', None)
        if 'apiKey' in data:
            setting.apiKey = data.pop('apiKey')
        serializer = IntegrationSettingSerializer(setting, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            setting.save()
            response_serializer = IntegrationSettingSerializer(setting)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)