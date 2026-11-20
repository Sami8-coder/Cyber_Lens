from django import forms
import urllib.parse
from scanner.ssrf import SSRFValidator, SSRFProtectionError

class ScanSubmissionForm(forms.Form):
    target_url = forms.CharField(
        max_length=500,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-lg',
            'placeholder': 'Enter target domain or URL (e.g. example.com or https://site.org)',
            'autocomplete': 'off',
            'required': True,
        }),
        help_text="Passive security posture audit only. No intrusive or offensive scans are executed."
    )
    scan_depth = forms.ChoiceField(
        choices=[
            ('standard', 'Standard Assessment (Headers, TLS, Cookies, DNS, Redirection)'),
            ('quick', 'Quick Audit (Headers & TLS Validation)'),
            ('deep', 'Deep Assessment (Full Cryptography, SPF/DMARC/CAA Analysis)'),
        ],
        initial='standard',
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )
    is_public = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        help_text="Allow public viewing of this assessment report via link."
    )

    def clean_target_url(self):
        url = self.cleaned_data.get('target_url', '').strip()
        if not url:
            raise forms.ValidationError("Please provide a valid website URL or domain.")

        # Ensure schema
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url

        try:
            # Perform SSRF and hostname verification
            normalized_url, hostname, ip = SSRFValidator.validate_and_resolve(url)
        except SSRFProtectionError as err:
            raise forms.ValidationError(f"Invalid target: {err}")
        except Exception as e:
            raise forms.ValidationError(f"Failed to resolve target: {e}")

        return normalized_url
