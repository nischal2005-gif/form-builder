from django.http import JsonResponse
from .models import Form
import re
import logging

logger = logging.getLogger(__name__)

class APIKeyAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Update this pattern to match your actual URL
        self.api_pattern = re.compile(r'^/forms/(?P<form_id>[^/]+)/?$')


    def __call__(self, request):
        # Debug logging
        
        # Check if request matches API pattern
        match = self.api_pattern.match(request.path)
        if match and request.method == 'POST':
            form_id = match.group('form_id')
            logger.debug(f"Processing API submission for form {form_id}")
            
            try:
                form = Form.objects.get(id=form_id)
                
                # Get API key from headers (case-insensitive) or POST data
                api_key = None
                for header, value in request.headers.items():
                    if header.lower() == 'x-api-key':
                        api_key = value
                        break
                
                # Fallback to POST data if not in headers
                if not api_key and request.method == 'POST':
                    api_key = request.POST.get('api_key')
                
                logger.debug(f"Received API key: {api_key}")
                logger.debug(f"Expected API key: {form.api_key}")
                
                if not api_key:
                    logger.warning("Missing API key")
                    return JsonResponse({
                        'error': 'Missing API key',
                        'required_header': 'X-API-KEY',
                        'status': 401
                    }, status=401)
                
                if api_key != form.api_key:
                    logger.warning("Invalid API key provided")
                    return JsonResponse({
                        'error': 'Invalid API key',
                        'status': 403
                    }, status=403)
                
                # Add form to request for later use
                request.authenticated_form = form
                
            except Form.DoesNotExist:
                logger.error(f"Form not found: {form_id}")
                return JsonResponse({
                    'error': 'Form not found',
                    'status': 404
                }, status=404)
            except Exception as e:
                logger.error(f"Authentication error: {str(e)}")
                return JsonResponse({
                    'error': 'Authentication failed',
                    'details': str(e)
                }, status=500)
        
        return self.get_response(request)