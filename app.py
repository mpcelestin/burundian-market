from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy import or_
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask import abort


app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.secret_key = 'your-secret-key-here-change-this-for-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mugishapc1@gmail.com'
app.config['MAIL_PASSWORD'] = 'xxvdufnxrlvmrxwm'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@burundianmarket.com'
app.config['SECURITY_PASSWORD_SALT'] = 'your-salt-here-change-this'

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)  # Removed unique constraint
    password = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    user_type = db.Column(db.String(10), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    def __repr__(self):
        return f'<User {self.username}>'

class Product(db.Model):
    __tablename__ = 'products'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    image = db.Column(db.String(200), nullable=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    seller = db.relationship('User', backref=db.backref('products', lazy=True))
    
    def __repr__(self):
        return f'<Product {self.title}>'

# Create tables
with app.app_context():
    db.drop_all()  # Drop existing tables
    db.create_all()  # Create new tables with updated schema

# Helper Functions
def send_verification_email(email, token):
    verify_url = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email Address', recipients=[email])
    msg.body = f'''Welcome to Burundian Market!
    
Please click the following link to verify your email address:
{verify_url}

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

def send_password_reset_email(email, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not request a password reset, please ignore this email.
'''
    mail.send(msg)

# Routes
@app.route('/')
def home():
    products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone = request.form.get('phone')
        user_type = request.form['user_type']
        
        # Only check for username (email check removed)
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create user (email duplicates now allowed)
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            phone=phone,
            user_type=user_type
        )
        
        # Generate verification token
        token = serializer.dumps(email, salt='email-verification')
        new_user.verification_token = token
        
        db.session.add(new_user)
        db.session.commit()
        
        # Send verification email
        send_verification_email(new_user.email, token)
        
        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(email=email).first_or_404()
    
    if user.email_verified:
        flash('Account already verified. Please login.', 'info')
    else:
        user.email_verified = True
        user.is_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # Could be email or username
        password = request.form.get('password')

        if not identifier or not password:
            flash('Please enter both identifier and password.', 'danger')
            return redirect(url_for('login'))

        # Find user by email or username
        users = User.query.filter((User.email == identifier) | (User.username == identifier)).all()

        if not users:
            flash('No account found with this email or username.', 'danger')
            return redirect(url_for('login'))

        # Check each user's password
        authenticated_user = None
        for user in users:
            if check_password_hash(user.password, password):
                authenticated_user = user
                break

        if authenticated_user:
            if not authenticated_user.email_verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))

            # Set session
            session['user_id'] = authenticated_user.id
            session['user_type'] = authenticated_user.user_type
            flash('Login successful!', 'success')

            # Redirect based on role
            if authenticated_user.user_type == 'seller':
                return redirect(url_for('seller_dashboard'))
            else:
                return redirect(url_for('buyer_dashboard'))
        else:
            flash('Invalid password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/seller/dashboard')
def seller_dashboard():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    products = Product.query.filter_by(seller_id=user.id).order_by(Product.created_at.desc()).all()
    return render_template('seller_dashboard.html', user=user, products=products)

@app.route('/buyer/dashboard')
def buyer_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    categories = db.session.query(Product.category.distinct()).filter(Product.category.isnot(None)).all()
    categories = [c[0] for c in categories if c[0]]
    
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('buyer_dashboard.html', products=products, categories=categories)

@app.route('/product/add', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session or session['user_type'] != 'seller':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form.get('category')
        
        # Handle image upload
        image = request.files.get('image')
        image_url = None
        
        if image and image.filename != '':
            # Create uploads folder if it doesn't exist
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # Secure filename and save
            filename = f"product_{session['user_id']}_{len(Product.query.all()) + 1}.jpg"
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            image_url = f"uploads/{filename}"
        
        new_product = Product(
            title=title,
            description=description,
            price=price,
            category=category,
            image=image_url,
            seller_id=session['user_id']
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('seller_dashboard'))
    
    return render_template('add_product.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    seller = User.query.get(product.seller_id)
    
    # Check if the current user is the seller
    is_seller = 'user_id' in session and session['user_id'] == product.seller_id
    
    return render_template('product_detail.html', product=product, seller=seller, is_seller=is_seller)

@app.route('/products/search')
def product_search():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    products_query = Product.query
    
    if query:
        products_query = products_query.filter(
            or_(
                Product.title.ilike(f'%{query}%'),
                Product.description.ilike(f'%{query}%')
            )
        )
    
    if category:
        products_query = products_query.filter_by(category=category)
    
    products = products_query.order_by(Product.created_at.desc()).all()
    
    categories = db.session.query(Product.category.distinct()).filter(Product.category.isnot(None)).all()
    categories = [c[0] for c in categories if c[0]]
    
    return render_template(
        'product_search.html',
        products=products,
        search_query=query,
        categories=categories,
        selected_category=category
    )

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = serializer.dumps(email, salt='password-reset')
            send_password_reset_email(user.email, token)
        
        flash('If an account exists with that email, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user.password = generate_password_hash(password)
        db.session.commit()
        
        flash('Your password has been updated! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Check if username is already taken by another user
        new_username = request.form.get('username')
        if new_username != user.username and User.query.filter_by(username=new_username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('edit_profile'))
        
        user.username = new_username
        user.phone = request.form.get('phone', user.phone)
        
        # Handle password change
        new_password = request.form.get('new_password')
        if new_password and len(new_password) >= 6:
            user.password = generate_password_hash(new_password)
        elif new_password:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('edit_profile'))
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('seller_dashboard' if user.user_type == 'seller' else 'buyer_dashboard'))
    
    return render_template('edit_profile.html', user=user)

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Delete all user's products first (if seller)
    if user.user_type == 'seller':
        Product.query.filter_by(seller_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    # Clear session
    session.clear()
    flash('Your account has been permanently deleted', 'info')
    return redirect(url_for('home'))

@app.route('/product/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        abort(403)  # Forbidden for buyers
    
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    if request.method == 'POST':
        product.title = request.form['title']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.category = request.form.get('category')
        
        # Handle image update
        image = request.files.get('image')
        if image and image.filename != '':
            upload_folder = os.path.join(app.root_path, 'static', 'uploads')
            filename = f"product_{session['user_id']}_{product_id}.jpg"
            image_path = os.path.join(upload_folder, filename)
            image.save(image_path)
            product.image = f"uploads/{filename}"
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('seller_dashboard'))
    
    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        abort(403)  # Forbidden for buyers
    
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)  # Forbidden for other sellers
    
    # Delete product image if exists
    if product.image:
        try:
            os.remove(os.path.join(app.root_path, 'static', product.image))
        except:
            pass
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('seller_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)