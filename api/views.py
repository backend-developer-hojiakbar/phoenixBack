from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated

from .models import User, Journal, Article, Issue, AuditLog, IntegrationSetting
from .serializers import (
    UserSerializer, JournalSerializer, ArticleSerializer,
    IssueSerializer, AuditLogSerializer, IntegrationSettingSerializer
)
from .permissions import IsAdminUser, IsJournalManager, IsClientUser, IsOwnerOrAdmin, IsAssignedEditorOrAdmin


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


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]


class JournalViewSet(viewsets.ModelViewSet):
    queryset = Journal.objects.all()
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
            return Journal.objects.filter(manager=user)
        return super().get_queryset()


class ArticleViewSet(viewsets.ModelViewSet):
    queryset = Article.objects.all().order_by('-submittedDate')
    serializer_class = ArticleSerializer

    def get_permissions(self):
        if self.action == 'create':
            self.permission_classes = [IsClientUser]
        elif self.action in ['update', 'partial_update']:
            self.permission_classes = [IsAssignedEditorOrAdmin]
        elif self.action == 'destroy':
            self.permission_classes = [IsAdminUser]
        else:
            self.permission_classes = [permissions.IsAuthenticated]
        return super().get_permissions()

    def get_queryset(self):
        user = self.request.user
        if user.role == User.Role.CLIENT:
            return Article.objects.filter(author=user)
        elif user.role == User.Role.JOURNAL_MANAGER:
            return Article.objects.filter(assignedEditor=user)
        elif user.role == User.Role.ADMIN:
            return Article.objects.all()
        return Article.objects.none()

    def perform_create(self, serializer):
        journal = serializer.validated_data.get('journal')
        assigned_editor = None
        if journal and journal.manager:
            assigned_editor = journal.manager
        serializer.save(author=self.request.user, assignedEditor=assigned_editor)


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
                                                         status=Article.ArticleStatus.PENDING).count(),
                'reviewing': Article.objects.filter(assignedEditor=user,
                                                    status=Article.ArticleStatus.REVIEWING).count(),
            }
        elif user.role == User.Role.ADMIN:
            data = {
                'totalUsers': User.objects.count(),
                'totalJournals': Journal.objects.count(),
                'totalArticles': Article.objects.count(),
                'pendingAll': Article.objects.filter(status=Article.ArticleStatus.PENDING).count(),
            }
        return Response(data)


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

    def patch(self, request, service_name, *args, **kwargs):
        try:
            setting = IntegrationSetting.objects.get(serviceName=service_name)
            if 'apiKey' in request.data:
                setting.apiKey = request.data.get('apiKey')

            serializer = IntegrationSettingSerializer(setting, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                response_serializer = IntegrationSettingSerializer(setting)
                return Response(response_serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except IntegrationSetting.DoesNotExist:
            return Response({'error': 'Setting not found'}, status=status.HTTP_404_NOT_FOUND)