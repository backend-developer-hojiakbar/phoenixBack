from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView, LoginView, UserViewSet, JournalViewSet,
    ArticleViewSet, IssueViewSet, AuditLogViewSet, ProfileView,
    DashboardSummaryView, SystemSettingsView, SystemSettingsDetailView,
    AdminPaymentApprovalView, FinancialReportsView, JournalTypesView,
    JournalCategoryViewSet
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'journals', JournalViewSet, basename='journal')
router.register(r'journal-categories', JournalCategoryViewSet, basename='journalcategory')
router.register(r'articles', ArticleViewSet, basename='article')
router.register(r'issues', IssueViewSet)
router.register(r'audit-logs', AuditLogViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('dashboard-summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
    path('financial-reports/', FinancialReportsView.as_view(), name='financial-reports'),
    path('journal-types/', JournalTypesView.as_view(), name='journal-types'),
    path('system-settings/', SystemSettingsView.as_view(), name='system-settings-list'),
    path('system-settings/<str:service_name>/', SystemSettingsDetailView.as_view(), name='system-settings-detail'),
    path('admin/approve-payment/<int:article_id>/', AdminPaymentApprovalView.as_view(), name='admin-approve-payment'),
]