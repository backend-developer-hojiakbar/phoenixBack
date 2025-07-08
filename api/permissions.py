from rest_framework import permissions
from .models import User, Article

class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == User.Role.ADMIN

class IsJournalManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == User.Role.JOURNAL_MANAGER

class IsClientUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == User.Role.CLIENT

class IsAccountantUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == User.Role.ACCOUNTANT

class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.role == User.Role.ADMIN:
            return True
        if isinstance(obj, Article):
            return obj.author == request.user
        return obj == request.user

class IsAssignedEditorOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.role == User.Role.ADMIN:
            return True
        if request.user.role == User.Role.JOURNAL_MANAGER and isinstance(obj, Article):
            return obj.assignedEditor == request.user and obj.submissionPaymentStatus == Article.PaymentStatus.PAYMENT_APPROVED_PROCESSING
        return False