from django.views.generic.base import View
from django.core.urlresolvers import reverse
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required


class HomePage(View):  # RedirectView

    def get(self, request):
        return redirect(reverse('login'))


class PrimaryNavigation(View):  # TemplateView
    
    template_name = 'monitors/dashboard.html'

    @method_decorator(login_required(login_url='login'))
    def get(self, request):

        return render(request, self.template_name)