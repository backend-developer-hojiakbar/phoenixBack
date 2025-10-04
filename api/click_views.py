import hashlib
from datetime import datetime
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .models import ClickTransaction, Article, ServiceOrder


class ClickPrepareView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        click_trans_id = request.data.get('click_trans_id')
        service_id = request.data.get('service_id')
        merchant_trans_id = request.data.get('merchant_trans_id')
        amount = request.data.get('amount')
        action = request.data.get('action')
        sign_time = request.data.get('sign_time')
        sign_string = request.data.get('sign_string')

        md5_hash = hashlib.md5(
            f"{click_trans_id}{service_id}{settings.CLICK_SECRET_KEY}{merchant_trans_id}{amount}{action}{sign_time}".encode()).hexdigest()
        if sign_string != md5_hash:
            return Response({'error': -1, 'error_note': 'SIGN CHECK FAILED!'})

        try:
            transaction = ClickTransaction.objects.get(merchant_trans_id=merchant_trans_id)
        except ClickTransaction.DoesNotExist:
            return Response({'error': -5, 'error_note': 'Transaction does not exist'})

        if action == '0':
            if transaction.status != ClickTransaction.Status.WAITING:
                return Response({'error': -4, 'error_note': 'Transaction already processed'})

            if str(transaction.amount) != str(amount):
                return Response({'error': -2, 'error_note': 'Incorrect parameter amount'})

            transaction.status = ClickTransaction.Status.PREPARED
            transaction.click_trans_id = click_trans_id
            transaction.save()

            return Response({
                'click_trans_id': click_trans_id,
                'merchant_trans_id': merchant_trans_id,
                'merchant_prepare_id': transaction.id,
                'error': 0,
                'error_note': 'Success'
            })

        return Response({'error': -1, 'error_note': 'Unknown action'})


class ClickCompleteView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        click_trans_id = request.data.get('click_trans_id')
        service_id = request.data.get('service_id')
        merchant_trans_id = request.data.get('merchant_trans_id')
        merchant_prepare_id = request.data.get('merchant_prepare_id')
        amount = request.data.get('amount')
        action = request.data.get('action')
        error = request.data.get('error')
        sign_time = request.data.get('sign_time')
        sign_string = request.data.get('sign_string')

        md5_hash = hashlib.md5(
            f"{click_trans_id}{service_id}{settings.CLICK_SECRET_KEY}{merchant_trans_id}{merchant_prepare_id}{amount}{action}{sign_time}".encode()).hexdigest()

        if sign_string != md5_hash:
            return Response({'error': -1, 'error_note': 'SIGN CHECK FAILED!'})

        try:
            transaction = ClickTransaction.objects.get(id=merchant_prepare_id, merchant_trans_id=merchant_trans_id)
        except ClickTransaction.DoesNotExist:
            return Response({'error': -6, 'error_note': 'Transaction does not exist'})

        if transaction.status == ClickTransaction.Status.COMPLETED:
            return Response({'error': -4, 'error_note': 'Already paid'})

        if str(transaction.amount) != str(amount):
            return Response({'error': -2, 'error_note': 'Incorrect parameter amount'})

        if action == '1':
            if error == '0':
                transaction.status = ClickTransaction.Status.COMPLETED
                transaction.save()

                related_object = transaction.content_object
                if isinstance(related_object, Article):
                    related_object.submissionPaymentStatus = Article.PaymentStatus.PAYMENT_COMPLETED
                    related_object.status = Article.ArticleStatus.REVIEWING
                    related_object.save()
                elif isinstance(related_object, ServiceOrder):
                    related_object.status = ServiceOrder.Status.IN_PROGRESS
                    related_object.save()

                return Response({
                    'click_trans_id': click_trans_id,
                    'merchant_trans_id': merchant_trans_id,
                    'merchant_confirm_id': transaction.id,
                    'error': 0,
                    'error_note': 'Success'
                })
            else:
                transaction.status = ClickTransaction.Status.CANCELLED
                transaction.extra_data['cancel_error_code'] = error
                transaction.save()
                return Response({
                    'click_trans_id': click_trans_id,
                    'merchant_trans_id': merchant_trans_id,
                    'error': -9,
                    'error_note': 'Payment cancelled'
                })

        return Response({'error': -1, 'error_note': 'Unknown action'})