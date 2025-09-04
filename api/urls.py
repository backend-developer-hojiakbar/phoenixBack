from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, LoginView, UserViewSet, JournalViewSet, ArticleViewSet,
    JournalCategoryViewSet, JournalTypeViewSet, EditorialBoardApplicationViewSet,
    FinancialReportAPIView, ApprovePaymentAPIView, ProfileView, SystemSettingsView,
    IssueViewSet, AuditLogViewSet, DashboardSummaryView
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'journals', JournalViewSet, basename='journal')
router.register(r'journal-categories', JournalCategoryViewSet, basename='journalcategory')
router.register(r'journal-types', JournalTypeViewSet, basename='journaltype')
router.register(r'articles', ArticleViewSet, basename='article')
router.register(r'applications', EditorialBoardApplicationViewSet, basename='application')
router.register(r'issues', IssueViewSet, basename='issue')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('financial-report/', FinancialReportAPIView.as_view(), name='financial-report'),
    path('approve-payment/<int:article_id>/', ApprovePaymentAPIView.as_view(), name='approve-payment'),
    path('system-settings/', SystemSettingsView.as_view(), name='system-settings'),
    path('dashboard-summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
]