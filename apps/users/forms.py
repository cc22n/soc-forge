"""User forms for SOC Forge."""

import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

User = get_user_model()

# Allowed pattern for usernames: letters, digits, underscores, hyphens only
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class RegistrationForm(UserCreationForm):
    """
    Secure registration form.

    Security measures:
    - Inherits UserCreationForm: password hashing, mismatch check, strength
      validators from AUTH_PASSWORD_VALIDATORS (min 10 chars, common check…)
    - Email required and validated for uniqueness
    - Username restricted to [a-zA-Z0-9_-] to prevent homograph attacks
    - All fields stripped of leading/trailing whitespace
    - No raw SQL — Django ORM parameterizes all queries automatically
    """

    email = forms.EmailField(
        required=True,
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_username(self):
        username = self.cleaned_data.get("username", "").strip()
        if not _USERNAME_RE.match(username):
            raise forms.ValidationError(
                "Only letters, numbers, underscores and hyphens are allowed."
            )
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("That username is already taken.")
        return username

    def clean_email(self):
        email = self.cleaned_data.get("email", "").strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with that email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user
