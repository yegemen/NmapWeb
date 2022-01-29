from django.shortcuts import render, redirect
# user modelini dahil ettim. (setting.py deki auth)
from django.http import HttpResponse
# username ve password ile eşleşen kayıt var mı diye kontrol etmek ve session için
from django.contrib.auth.models import User
from django.contrib import auth
from django.contrib import messages  # uyarı msjları için
import nmap3
from whois import whois
from .models import Nmap, Who_is

# Create your views here.

# kullanıcı giriş
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        # kontrol burda yapılıyor.
        user = auth.authenticate(username=username, password=password)
        if user is not None:  # user objesi none değilse
            auth.login(request, user)  # session id oluşturur
            #messages.add_message(request, messages.SUCCESS, "Oturum Açıldı")
            return redirect('select')
        else:
            messages.add_message(request, messages.ERROR, "Hatalı Giriş !")
            return redirect('login')
    else:
        return render(request, 'pages/login.html')

# kullanıcı kayıt
def register(request):
    if request.method == 'POST':

        # bilgileri alıyorum

        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        repassword = request.POST['repassword']

        if password == repassword:  # parolalar uyuşuyorsa
            # veritabanında aynı kullanıcı var mı diye bakıyorum. eğer varsa true bilgi gelir.
            if User.objects.filter(username=username).exists():
                messages.add_message(
                    request, messages.WARNING, "Bu Kullanıcı Adı Daha Önce Alınmış.")
                return redirect('register')
            else:
                if User.objects.filter(email=email).exists():
                    messages.add_message(
                        request, messages.WARNING, "Bu E-Mail Daha Önce Alınmış.")
                    return redirect('register')
                else:
                    # herşey tamam
                    user = User.objects.create_user(
                        username=username, password=password, email=email)  # burda veritabanına kullanıcı bilgilerini gönderdim.
                    user.save()
                    messages.add_message(
                        request, messages.SUCCESS, "Hesabınız Oluşturuldu.")
                    return redirect('login')

        else:
            messages.add_message(request, messages.WARNING,
                                 "Parolalar Uyuşmuyor.")
            return redirect('register')

    else:
        return render(request, 'pages/register.html')

# Nmap taraması ve veritabanına kayıt
def scan(request):
    nmap = nmap3.Nmap()

    if request.method == 'POST':
        ip = request.POST['ip']
        type = request.POST['type']
        category = request.POST['category']

        script = f"--script {category}"

        if category == "":
            script = ""

        results = nmap.scan_top_ports(
            f"{str(ip)}", args=f"{type} -sV -top-ports 1000 {script}")

        a = results[str(ip)]['ports']

        context = {
            "scan": [],
            "targetIP": ip
        }

        for i in a:
            context["scan"].append(f"PORT: {i['portid']}")
            context["scan"].append(f"DURUM: {i['state']}")
            context["scan"].append(f"SERVİS/VERSİYON: {i['service']}")
            context["scan"].append(f"SCRIPT SONUCU: {i['scripts']}")
            context["scan"].append("xxx")

        port = ""
        state = ""
        service = ""
        script = ""
        
        for i in a:
            port += f"{i['portid']} , "
            state += f"{i['portid']}: {i['state']} , "
            service += f"{i['portid']}: {i['service']} , "
            script += f"{i['portid']}: {i['scripts']} , "

        current_user = request.user  # oturum açan kullanıcı bilgisi.

        Nmap.objects.create(host_ip=ip, scan_type=type, port=port, state=state,
                            service=service, script=script, user_id=current_user.id)  # veritabanı kayıt

        return render(request, "pages/scan.html", context)

    else:
        return render(request, "pages/scan.html")

# whois sorgulaması ve veritabanına kayıt
def who_is(request):

    if request.method == 'POST':
        domain = request.POST['domain']
        w = whois(f'{domain}')

        domain_name = w['domain_name']
        registrar = w['registrar']
        whois_server = w['whois_server']
        referral_url = w['referral_url']
        updated_date = w['updated_date']
        creation_date = w['creation_date']
        expiration_date = w['expiration_date']
        name_servers = w['name_servers']
        status = w['status']
        emails = w['emails']
        dnssec = w['dnssec']
        name = w['name']
        org = w['org']
        address = w['address']
        city = w['city']
        state = w['state']
        zipcode = w['zipcode']
        country = w['country']

        current_user = request.user  # oturum açan kullanıcı bilgisi.
        
        Who_is.objects.create(domain_name=domain_name, registrar=registrar, whois_server=whois_server, referral_url=referral_url, updated_date=updated_date,creation_date=creation_date, expiration_date=expiration_date, name_servers=name_servers, status=status, emails=emails, dnssec=dnssec, name=name, org=org,address=address, city=city, state=state, zipcode=zipcode, country=country, user_id=current_user.id)  # veritabanı kayıt

        return render(request, "pages/who_is.html", w)

    else:
        return render(request, "pages/who_is.html")

# Seçim sayfası
def select(request):
    return render(request, "pages/select.html")

# Nmap geçmiş taramalar
def past_scanning(request):
    current_user = request.user
    # tabloadi.object ile objelere ulaşılır
    # giriş yapan kullanıcının tarama sonuçları
    pastscan = Nmap.objects.filter(user_id=current_user.id)
    context = {
        'pastscan': pastscan
    }
    return render(request, "pages/past_scanning.html", context)

# whois geçmiş taramalar
def past_scanning_whois(request):
    current_user = request.user
    # giriş yapan kullanıcının tarama sonuçları
    pastscan = Who_is.objects.filter(user_id=current_user.id)
    context = {
        'pastscan': pastscan
    }
    return render(request, "pages/past_scanning_whois.html", context)

# oturumu kapat
def logout(request):
    if request.method == 'POST':
        auth.logout(request)
        messages.add_message(request, messages.SUCCESS,
                             'Oturumunuz kapatıldı.')
        return redirect('login')
