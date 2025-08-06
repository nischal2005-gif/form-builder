from django import template

register = template.Library()

@register.filter
def split_choices(value):
    """Splits a comma-separated string into a list."""
    if isinstance(value, str):
        return [choice.strip() for choice in value.split(',')]
    return []
