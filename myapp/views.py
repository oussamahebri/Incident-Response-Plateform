import google.generativeai as genai

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Feature
from .models import Alert
from django.http import JsonResponse
from django.db.models import Count
from .forms import CreateUserForm
from .forms import ProfileForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from sqlalchemy import create_engine, text
# Create your views here.

# Configure your Gemini API key
genai.configure(api_key="Replace with your actual API key") 

model_name = 'models/gemini-1.5-pro' 
model = genai.GenerativeModel(model_name)

@login_required(login_url='login')
def index(request):
    alerts = Alert.objects.all()

    # Compter les alertes selon leur criticité
    critical = alerts.filter(criticity='critical').count()
    medium = alerts.filter(criticity='medium').count()
    pending_status = alerts.filter(status='pending').count()
    resolved_status = alerts.filter(status='resolved').count()
    error_status = alerts.filter(status='error').count()

    # Top 5 Targets (les machines les plus attaquées)
    top_targets = (
        Alert.objects.values("target_name", "target_ip")
        .annotate(incident_count=Count("alert_id"))
        .order_by("-incident_count")[:5]
    )

    # Top 5 Attackers (les IP attaquantes les plus actives)
    top_attackers = (
        Alert.objects.values("attacker")
        .annotate(attack_count=Count("alert_id"))
        .order_by("-attack_count")[:5]
    )

    # Classification des attaques selon alert_desc
    attack_patterns = {
        "Brute Force": ["brute force", "failed login", "multiple login attempts"],
        "Malware": ["malware", "trojan", "ransomware", "VirusTotal"],
        "DDoS": ["denial of service", "ddos", "botnet"],
        "Port Scan": ["port scan", "reconnaissance"],
        "SQL Injection": ["sql injection", "database error", "sql syntax"],
    }

    # Top 5 Attacks (types d'attaques les plus fréquents)
    attack_counts = {}
    for attack_type, keywords in attack_patterns.items():
        attack_counts[attack_type] = (
            Alert.objects.filter(
                alert_desc__iregex="|".join(keywords)  # Recherche insensible à la casse
            ).count()
        )

    # Trier les attaques par fréquence et garder les 5 plus courantes
    top_attacks = sorted(
        attack_counts.items(), key=lambda x: x[1], reverse=True
    )[:5]


    # Passer les données au template
    context = {
        'critical': critical,
        'medium': medium,
        'pending_status': pending_status,
        'resolved_status': resolved_status,
        'error_status': error_status,
        "top_targets": top_targets,
        "top_attackers": top_attackers,
        "top_attacks": top_attacks,
    }
    return render(request, 'index.html', context)
   
@login_required(login_url='login')
def alerts(request):
    alerts = Alert.objects.all()
    return render(request, 'wazuh.html', {'alerts': alerts})


engine = create_engine("mysql+pymysql://django:django@192.168.1.100/alerts_db")


def chatbot(request):
    query = request.GET.get("query", "").lower()

    table_structure = """
    Table: alert
    Columns:
    - alert_id (INT, AUTO_INCREMENT, PRIMARY KEY)
    - rule_id (INT, NOT NULL)
    - timestamp (DATETIME, DEFAULT CURRENT_TIMESTAMP)
    - criticity (ENUM('low', 'medium', 'critical'), NOT NULL)
    - target_name (VARCHAR(255), NOT NULL)
    - target_ip (VARCHAR(50), NOT NULL)
    - attacker (VARCHAR(50), NOT NULL)
    - alert_desc (TEXT, NOT NULL)
    - status (ENUM('pending', 'resolved', 'error'), DEFAULT 'pending')
    - Incident_Response_Desc (TEXT)
    """

    prompt = f"""
    {table_structure}
    Convert this natural language question into a MySQL query for the 'alert' table, considering the table structure above: {query}.
    Only return the SQL query without explanation. If the question does not require a SQL query, return 'NON_SQL'
    """

    try:
        response = model.generate_content(prompt)
        sql_query = response.text.strip()
        sql_query = sql_query.replace("```sql", "").replace("```", "").strip()

        if sql_query.upper() != "NON_SQL":
            if "SELECT" in sql_query.upper():
                try:
                    with engine.connect() as connection:
                        result = connection.execute(text(sql_query))
                        rows = result.fetchall()
                        if len(rows) == 1 and len(rows[0]) == 1:
                            return JsonResponse({"response": str(rows[0][0])})
                        elif len(rows) >= 0:
                            formatted_rows = [str(row) for row in rows]
                            return JsonResponse({"response": ", ".join(formatted_rows)})
                        else :
                            return JsonResponse({"response": "No Results"})

                except Exception as e:
                    return JsonResponse({"response": f"SQL Error: {str(e)}"})
            else:
                return JsonResponse({"response": "Invalid SQL Query"})
        else:
            gemini_prompt = f"You are a cybersecurity assistant. Answer this: {query}"
            gemini_response = model.generate_content(gemini_prompt)
            return JsonResponse({"response": gemini_response.text})

    except Exception as e:
        return JsonResponse({"response": f"Gemini Error: {str(e)}"})

@login_required(login_url='login')    
def chat_page(request):
    return render(request, 'chatbot.html')


def loginPage(request):
    if request.user.is_authenticated:
        return redirect("/")
    else:
        if request.method == 'POST' :
            username = request.POST.get('username')
            password = request.POST.get('password')

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                return redirect("/")
            else:
                messages.info(request, 'Username OR password is incorrect')

    return render(request, 'login.html')

def registerPage(request): 
    if request.user.is_authenticated:
        return redirect("/")
    else: 
        form = CreateUserForm()
        if request.method == 'POST':
            form = CreateUserForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Account was created')
                return redirect('login')
            else:
                errors = form.errors.as_text()  # Récupérer les erreurs en texte
                messages.error(request, f'There are errors in your input: {errors}')
    return render(request, 'register.html', {'form': form})


def logoutUser(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login')
def profile(request):
    if request.method == "POST":
        user = request.user
        username = request.POST.get("username")
        email = request.POST.get("email")

        # Update username and email
        user.username = username
        user.email = email
        user.save()

        # Handle password change
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if old_password and new_password and new_password == confirm_password:
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)  # Keep user logged in after password change
            else:
                return render(request, "profile.html", {"error": "Incorrect current password."})

        return redirect("profile")

    return render(request, "profile.html")