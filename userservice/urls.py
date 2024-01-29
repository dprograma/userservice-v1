from django.urls import path

from userservice.views import (
    SendEmailOTPView,
    SendPhoneOTPView,
    VerifyOTPView,
    DeleteAccountView,
    ForgotPasswordView,
    LoginView,
    LogoutView,
    PasswordResetView,
    SignupView,
    UpdateUserView,
)


urlpatterns = [
    path("signup/", SignupView.as_view(), name="signup"),
    # http://127.0.0.1:8000/gateway/api/v1/signup
    path("login/", LoginView.as_view(), name="login"),
    path("send-email-otp/", SendEmailOTPView.as_view(), name="send_email_otp"),
    path("send-phone-otp/", SendPhoneOTPView.as_view(), name="send_phone_otp"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify_otp"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("forgot-password/", ForgotPasswordView.as_view(), name="forgot_password"),
    path(
        "reset-password/",
        PasswordResetView.as_view(),
        name="reset_password",
    ),
    path("update-user/", UpdateUserView.as_view(), name="update_user"),
    path("delete-account/", DeleteAccountView.as_view(), name="delete_account"),
]
