from django import template
register = template.Library()

@register.filter(name='get')
def get(obj, key):
    if key not in obj:
        raise Exception('Key not found')
    return obj[key]