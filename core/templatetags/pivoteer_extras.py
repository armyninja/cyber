from django import template

from core.utilities import check_ip_valid
from core.utilities import check_domain_valid
from core.utilities import check_email_valid

register = template.Library()

@register.filter(name='verify_type')
def verify_type(value, validator):

    if validator == "ip":
        return check_ip_valid(value)

    elif validator == "domain":
        return check_domain_valid(value)

    elif validator == "email":
        return check_email_valid(value)

    else:
        return False