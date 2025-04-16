






import os
import smtplib
import ssl
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import check_password_hash, generate_password_hash
from market.forms import RegisterForm, LoginForm, ChatForm, CampaignForm, TipForm
from flask_mail import Message as MailMessage

import sqlite3
from datetime import datetime

from flask import (flash, get_flashed_messages, jsonify, redirect, render_template, request, url_for)
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from market import app, bcrypt, db, login_manager
from market.forms import LoginForm, PurchaseItemForm, RegisterForm
from market.models import Illness, Item, User, Veterinary, Campaign, Notification, Tip, Message


@app.route('/')
def welcome_page():
    return render_template('welcome-page.html')


@app.route('/home')
def home_page():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    else:
        unread_count = 0
    return render_template('home.html', unread_count=unread_count)
    #  we went on to call the home.html file as can be seen above.
    # 'render_template()' basically works by rendering files.

#@login_required
#below list of dictionaries is sent to the market page through the market.html
#       but we are going to look for a way to store information inside an organized
#       DATABASE which can be achieved through configuring a few things in our flask
#       application
# WE ARE THUS GOING TO USE SQLITE3 is a File WHich allows us to store information and we are going to
#   connect it to the Flask APplication.We thus have to install some flask TOOL THAT ENABLES THIS through the terminal


# Email configuration
EMAIL_SENDER = 'magero833@gmail.com'
EMAIL_PASSWORD = "gdtd gmuk bddl retb"  # App-specific password for Gmail

# Token generator for email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])



# VetConnect Alerts
def send_vetconnect_alert(recipient_email, subject, body):
    from market import mail
    msg = MailMessage(subject=subject, recipients=[recipient_email], body=body)
    try:
        mail.send(msg)
        print(f"Sent alert to {recipient_email}: {subject}")
    except Exception as e:
        print(f"Failed to send alert to {recipient_email}: {e}")



def send_verification_email(email_receiver, username, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    subject = 'Verify Your Email to Create Your Account'
    body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                text-align: center;
                padding: 20px 0;
                background-color: #D2B48C;
                color: white;
                border-radius: 8px 8px 0 0;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
            }}
            .content {{
                padding: 20px;
                color: #333;
            }}
            .content p {{
                line-height: 1.6;
                margin: 10px 0;
            }}
            .button {{
                display: inline-block;
                padding: 12px 25px;
                background-color: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                text-align: center;
            }}
            .button:hover {{
                background-color: #45a049;
            }}
            .footer {{
                text-align: center;
                padding: 10px;
                font-size: 12px;
                color: #777;
            }}
            .link {{
                word-break: break-all;
                color: #4CAF50;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="https://livestockanalytics.com/hs-fs/hubfs/Logos%20e%20%C3%ADconos/livestock.png?width=115&height=70&name=livestock.png" alt="Livestock Management" style="max-width: 150px;">
                <h1>Welcome to Livestock Management</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>Thank you for joining the Livestock Management System! To complete your account creation, please verify your email by clicking the button below:</p>
                <p style="text-align: center;">
                    <a href="{verification_url}" class="button">Create Account</a>
                </p>
                <p>If the button doesn’t work, copy and paste this link into your browser:</p>
                <p><a href="{verification_url}" class="link">{verification_url}</a></p>
                <p>This link expires in 1 hour.</p>
            </div>
            <div class="footer">
                <p>&copy; 2025 Livestock Management System. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    em = EmailMessage()
    em['From'] = EMAIL_SENDER
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body, subtype='html')  # Ensure HTML subtype is set

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.sendmail(EMAIL_SENDER, email_receiver, em.as_string())
        print(f"Verification email sent to {email_receiver}")
    except Exception as e:
        print(f"Email error: {str(e)}")



@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check for existing username or email
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", category='danger')
            return render_template('register.html', form=form)
        if User.query.filter_by(email_address=form.email_address.data).first():
            flash("Email already exists.", category='danger')
            return render_template('register.html', form=form)
        
        # Create new user
        new_user = User(
            username=form.username.data,
            email_address=form.email_address.data,
            password_hash=generate_password_hash(form.password1.data),
            role=form.role.data,
            email_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Create account creation notification
        notification = Notification(
            user_id=new_user.id,
            content=f"Welcome, {new_user.username}! Your account has been created successfully.",
            read=False,
            created_at=datetime.utcnow()
        )
        db.session.add(notification)
        db.session.commit()

        flash("Account created! Please verify your email.", category='success')
        return redirect(url_for('verify_pending', email=new_user.email_address))
    
    return render_template('register.html', form=form)


@app.route('/verify-pending/<email>')
def verify_pending(email):
    return render_template('verify_pending.html', email=email)


@app.route('/resend-verification/<email>')
def resend_verification(email):
    user = User.query.filter_by(email_address=email, email_verified=False).first()
    if user:
        token = s.dumps({'user_id': user.id, 'email': user.email_address}, salt='email-verify')
        send_verification_email(user.email_address, user.username, token)
        flash("A new verification email has been sent!", category='info')
    else:
        flash("No unverified account found for this email.", category='danger')
    return redirect(url_for('verify_pending', email=email))

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        # Verify token (expires in 3600 seconds = 1 hour)
        data = s.loads(token, salt='email-verify', max_age=3600)
        user_id = data['user_id']
        email = data['email']
        
        # Find user and verify email matches
        user = User.query.get(user_id)
        if user and user.email_address == email and not user.email_verified:
            user.email_verified = True
            db.session.commit()
            login_user(user)
            flash(f"Email verified! Welcome, {user.username}!", category='success')
            return redirect(url_for('welcome_page'))
        else:
            flash("Invalid or already verified account.", category='danger')
    except SignatureExpired:
        flash("The verification link has expired. Please register again.", category='danger')
    except BadSignature:
        flash("Invalid verification link.", category='danger')
    
    return redirect(url_for('register_page'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                if user.email_verified:
                    login_user(user)
                    notification = Notification(
                        user_id=user.id,
                        content=f"Welcome back, {user.username}! You have successfully logged in.",
                        read=False,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(notification)
                    db.session.commit()
                    flash(f"Welcome back, {user.username}!", category='success')
                    return redirect(url_for('home_page'))
                else:
                    flash("Please verify your email before logging in.", category='warning')
                    return redirect(url_for('verify_pending', email=user.email_address))
            else:
                flash("Incorrect password. Please try again.", category='danger')
                return render_template('login.html', form=form)
        else:
            flash("Username not found. Please register to create an account.", category='danger')
            return redirect(url_for('register_page'))
    
    return render_template('login.html', form=form)

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    form = ChatForm()
    user = current_user
    
    if user.role == 'farmer':
        form.receiver_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='vet').all()]
    else:
        form.receiver_id.choices = [(u.id, u.username) for u in User.query.filter_by(role='farmer').all()]
    
    if form.validate_on_submit():
        message = Message(
            sender_id=user.id,
            receiver_id=form.receiver_id.data,
            content=form.content.data
        )
        db.session.add(message)
        notification = Notification(
            user_id=form.receiver_id.data,
            content=f"New message from {user.username}"
        )
        db.session.add(notification)
        receiver = User.query.get(form.receiver_id.data)
        send_vetconnect_alert(
            receiver.email_address,
            "New Message in VetApp",
            f"Hi {receiver.username},\n\nYou have a new message from {user.username}: {form.content.data}\n\nCheck it at {url_for('chat', _external=True)}"
        )
        db.session.commit()
        flash("Message sent!", category='success')
        return redirect(url_for('chat'))
    
    sent = Message.query.filter_by(sender_id=user.id).order_by(Message.timestamp.desc()).all()
    received = Message.query.filter_by(receiver_id=user.id).order_by(Message.timestamp.desc()).all()
    
    return render_template('chat.html', form=form, sent=sent, received=received)

@app.route('/tips', methods=['GET', 'POST'])
def tips():
    form = TipForm()
    if current_user.role == 'vet' and form.validate_on_submit():
        tip = Tip(
            vet_id=current_user.id,
            content=form.content.data
        )
        db.session.add(tip)
        db.session.commit()
        flash("Tip posted!", category='success')
        return redirect(url_for('tips'))
    
    tips_list = Tip.query.order_by(Tip.posted_at.desc()).all()
    return render_template('tips.html', form=form, tips=tips_list)

@app.route('/campaigns', methods=['GET', 'POST'])
def campaigns():
    form = CampaignForm()
    if current_user.role == 'vet' and form.validate_on_submit():
        campaign = Campaign(
            title=form.title.data,
            description=form.description.data,
            location=form.location.data,
            date=form.date.data,
            organizer=form.organizer.data
        )
        db.session.add(campaign)
        farmers = User.query.filter_by(role='farmer').all()
        for farmer in farmers:
            notification = Notification(
                user_id=farmer.id,
                content=f"New campaign: {form.title.data} in {form.location.data}"
            )
            db.session.add(notification)
            send_vetconnect_alert(
                farmer.email_address,
                "New Veterinary Campaign",
                f"Hi {farmer.username},\n\nA new campaign '{form.title.data}' is scheduled in {form.location.data} on {form.date.data.strftime('%Y-%m-%d %H:%M')}.\n\nDetails: {form.description.data}\n\nView at {url_for('campaigns', _external=True)}"
            )
        db.session.commit()
        flash("Campaign posted!", category='success')
        return redirect(url_for('campaigns'))
    
    campaigns_list = Campaign.query.order_by(Campaign.date.asc()).all()
    return render_template('campaigns.html', form=form, campaigns=campaigns_list)



@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id, read=False).order_by(Notification.created_at.desc()).all()
    for notif in notifications:
        notif.read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notifications)



@app.route('/notifications/count')
@login_required
def notifications_count():
    unread_count = Notification.query.filter_by(user_id=current_user.id, read=False).count()
    return jsonify({'unread_count': unread_count})
        
                
    
    
@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for("home_page"))



#added this code for the search bar at the navbar in 'base.html'
@app.route('/search', methods=['GET'])
def search_results():
    query = request.args.get('animal', '').strip()

    if not query:
        return render_template('livestock_dashboard.html', error="Please enter an animal name.")

    conn = get_db_connection()
    cur = conn.cursor()

    # Get animal ID
    cur.execute("SELECT id FROM Animals WHERE LOWER(name) = LOWER(?)", (query,))
    animal = cur.fetchone()
    if not animal:
        conn.close()
        return render_template('livestock_dashboard.html', error=f"No data found for {query}.", animal=query)
    animal_id = animal['id']

    # Fetch static data (no age range)
    cur.execute("SELECT name AS species_name FROM Species WHERE animal_id = ?", (animal_id,))
    species = cur.fetchone()

    cur.execute("SELECT preferred_conditions AS habitat, temperature_range FROM Habitat WHERE animal_id = ?", (animal_id,))
    habitat = cur.fetchone()

    cur.execute("SELECT product_type AS produce FROM Produce WHERE animal_id = ?", (animal_id,))
    produce = cur.fetchone()

    # Fetch age-specific data
    cur.execute("SELECT age_range, feed_type, quantity_per_day FROM Feed WHERE animal_id = ?", (animal_id,))
    feeds = cur.fetchall()

    cur.execute("SELECT age_range, vaccine_name FROM VaccinationSchedule WHERE animal_id = ?", (animal_id,))
    vaccines = cur.fetchall()

    cur.execute("SELECT age_range, disease_name FROM Diseases WHERE animal_id = ?", (animal_id,))
    diseases = cur.fetchall()

    cur.execute("SELECT age_range, average_weight FROM WeightTracking WHERE animal_id = ?", (animal_id,))
    weights = cur.fetchall()

    cur.execute("SELECT age_range, supplement_name, dosage FROM AdditivesAndMinerals WHERE animal_id = ?", (animal_id,))
    supplements = cur.fetchall()

    conn.close()

    # Group age-specific data
    grouped_results = {}
    for table_data, key in [
        (feeds, 'feeds'), (vaccines, 'vaccines'), (diseases, 'diseases'),
        (weights, 'weights'), (supplements, 'supplements')
    ]:
        for row in table_data:
            age = row['age_range'] or 'Unknown'
            if age not in grouped_results:
                grouped_results[age] = {
                    'species_name': species['species_name'] if species else 'Not Available',
                    'habitat': habitat['habitat'] if habitat else 'Not Available',
                    'temperature_range': habitat['temperature_range'] if habitat else 'Not Available',
                    'produce': produce['produce'] if produce else 'Not Available',
                    'feeds': [], 'vaccines': [], 'diseases': [], 'weights': [], 'supplements': []
                }
            if key == 'feeds':
                grouped_results[age]['feeds'].append({'feed_type': row['feed_type'], 'quantity_per_day': row['quantity_per_day']})
            elif key == 'vaccines':
                grouped_results[age]['vaccines'].append(row['vaccine_name'])
            elif key == 'diseases':
                grouped_results[age]['diseases'].append(row['disease_name'])
            elif key == 'weights':
                grouped_results[age]['weights'].append(row['average_weight'])
            elif key == 'supplements':
                grouped_results[age]['supplements'].append({'supplement_name': row['supplement_name'], 'dosage': row['dosage']})

    if not grouped_results:
        return render_template('livestock_dashboard.html', error=f"No detailed data found for {query}.", animal=query)

    return render_template('livestock_dashboard.html', grouped_results=grouped_results, animal=query)
# Function to connect to SQLite
def get_db_connection():
    conn = sqlite3.connect('C:/Users/ADMIN/.vscode/.vscode/FlaskMarket/market.db')
    conn.row_factory = sqlite3.Row  # Allows fetching results as dictionaries
    return conn


# Age Calculator Route
@app.route('/livestock_dashboard/age_calculator', methods=['POST'])
def age_calculator():
    try:
        # Get form data
        dob_str = request.form['dob']
        calc_date_str = request.form['calc_date']
        format_choice = request.form['format_choice']

        # Convert strings to datetime objects
        dob = datetime.strptime(dob_str, '%Y-%m-%d')
        calc_date = datetime.strptime(calc_date_str, '%Y-%m-%d')

        # Validate dates
        if calc_date < dob:
            return jsonify({"error": "Calculate date must be after date of birth."})

        # Use relativedelta for precise age calculation
        delta = relativedelta(calc_date, dob)

        # Format result based on choice
        if format_choice == 'days':
            total_days = (calc_date - dob).days
            result = f"{total_days} days"
        elif format_choice == 'weeks':
            total_days = (calc_date - dob).days
            weeks = total_days // 7
            result = f"{weeks} weeks"
        elif format_choice == 'months':
            months = delta.years * 12 + delta.months
            result = f"{months} months"
        elif format_choice == 'years':
            years = delta.years
            result = f"{years} years"
        elif format_choice == 'ymd':
            result = f"{delta.years} years, {delta.months} months, {delta.days} days"

        return jsonify({"result": result})

    except ValueError:
        return jsonify({"error": "Invalid date format. Please use YYYY-MM-DD."})




def get_animal_info(animal_name):
    conn = sqlite3.connect('C:/Users/ADMIN/.vscode/.vscode/FlaskMarket/market.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM animals WHERE LOWER(name) = LOWER(?)", (animal_name,))
    animal = cursor.fetchone()
    conn.close()
    return animal


@app.route('/Privacy_page')
def Privacy_page():
    return render_template('Privacy_page.html')




@app.route('/nearby_vets')
def nearby_vets():
    vets = Veterinary.query.limit(6).all()  # First 6 vets for page 1
    return render_template('nearby-vets.html', vets=vets)

@app.route('/nearby-vets-2')
def nearby_vets_2():
    vets = Veterinary.query.offset(6).limit(6).all()  # Next 6 vets for page 2
    return render_template('nearby-vets-2.html', vets=vets)

@app.route('/nearby-vets-3')
def nearby_vets_3():
    vets = Veterinary.query.offset(12).limit(6).all()  # Next 6 vets for page 3
    return render_template('nearby-vets-3.html', vets=vets)

@app.route('/nearby-vets-4')
def nearby_vets_4():
    vets = Veterinary.query.offset(12).limit(6).all()  # Next 6 vets for page 3
    return render_template('nearby-vets-4.html', vets=vets)



@app.route('/schedule_appointment', methods=['POST'])
def schedule_appointment():
    vet_id = request.form.get('vet_id')
    appointment_date = request.form.get('appointmentDate')
    appointment_time = request.form.get('appointmentTime')
    animal_type = request.form.get('animalType')
    owner_name = request.form.get('ownerName')
    owner_email = request.form.get('ownerEmail')

    vet = Veterinary.query.get(vet_id)
    if vet:
        flash(f"Appointment booked with {vet.name} on {appointment_date} at {appointment_time} for your {animal_type}!", category='success')
    else:
        flash("Error booking appointment. Vet not found.", category='danger')
    
    return redirect(url_for('nearby_vets'))



@app.route('/home2_page')
def home2_page():
    return render_template('home2.html')


@app.route('/livestock_dashboard')
def livestock_dashboard():
    return render_template('livestock_dashboard.html')

@app.route('/near-veterinaries')
def near_veterinaries():
    return render_template('near-veterinaries.html')



@app.route('/symptom-checker', methods=['GET', 'POST'])
def symptom_checker():
    form = SymptomCheckerForm()
    result = None
    recommended_vet = None

    if form.validate_on_submit():
        user_symptoms = [symptom.strip().lower() for symptom in form.symptoms.data.split(',')]
        illnesses = Illness.query.all()
        best_match = None
        max_matches = 0

        for illness in illnesses:
            illness_symptoms = [symptom.strip().lower() for symptom in illness.symptoms.split(',')]
            matches = len(set(user_symptoms) & set(illness_symptoms))
            if matches > max_matches:
                max_matches = matches
                best_match = illness

        if best_match and max_matches > 0:
            result = {
                'illness': best_match.name,
                'matched_symptoms': max_matches,
                'total_symptoms': len(best_match.symptoms.split(',')),
                'required_specialist': best_match.required_specialist
            }
            recommended_vet = Veterinary.query.filter_by(specialty=best_match.required_specialist).first()
            if not recommended_vet:
                flash("No veterinary found for this specialty.", category='warning')
        else:
            flash("No matching illness found for the given symptoms.", category='danger')

    return render_template('symptom_checker.html', form=form, result=result, recommended_vet=recommended_vet)


@app.route('/connect-farmers')
def connect_farmers():
    farmers = Farmer.query.all()
    return render_template('connect-farmers.html', farmers=farmers)
