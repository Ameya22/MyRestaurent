from django.shortcuts import render, redirect
from django.http import HttpResponse
from . forms import UserForm
from . models import User
from django.contrib import messages

# Create your views here.

def registerUser(request):
    # return HttpResponse('This is user Registration form')
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            """ 1st way: Create the user using Form """
            # password = form.cleaned_data['password']
            # user = form.save(commit=False) # commit i False that means form is ready to be saved
            # user.set_password(password)
            # user.role = User.CUSTOMER
            # user.save()

            """ 2nd way: Create the user using create_user method in model """
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            user.role = User.CUSTOMER
            user.save()
            messages.success(request, 'Your account has been registered successfully !')
            return redirect('registerUser')
        else:
            print("Invalid form")
            print(form.errors)
    else:
        form = UserForm()
    context = {
        'form': form,
    }
    return render(request, 'accounts/registerUser.html', context)
