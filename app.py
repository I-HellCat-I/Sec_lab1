import os
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
import bleach
from argon2 import PasswordHasher

app = Flask(__name__)
app.json.ensure_ascii = False

# Конфигурация приложения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-lab-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/lab_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ================================
# Модели базы данных (Защита от SQLi через ORM)
# ================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('messages', lazy=True))


# Создание таблиц при запуске
with app.app_context():
    db.create_all()


# ================================
# Middleware для проверки JWT
# ================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Токен передается в заголовке Authorization: Bearer <token>
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token = auth_header.split(" ")[1] if len(auth_header.split(" ")) == 2 else None

        if not token:
            return jsonify({'message': 'Токен отсутствует!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                raise Exception("User not found")
        except Exception as e:
            return jsonify({'message': 'Токен недействителен или просрочен!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# ================================
# Эндпоинты (API)
# ================================

# Регистрация пользователя
@app.route('/auth/register', methods=['POST'])
def register():
    ph = PasswordHasher()
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Нужны username и password'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Пользователь уже существует'}), 400

    hashed_password = ph.hash(data['password'])
    new_user = User(username=data['username'], password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Пользователь успешно создан'}), 201


# 1) POST /auth/login - Аутентификация
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    ph = PasswordHasher()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Нужны username и password'}), 400

    user = User.query.filter_by(username=data['username']).first()
    pass_flag = False
    try:
        ph.verify(user.password_hash, data['password'])
        pass_flag = True
    except:
        pass


    if not user or not pass_flag:
        return jsonify({'message': 'Неверный логин или пароль'}), 401

    # Генерация JWT токена
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})


# 2) GET /api/data - Получение списка сообщений
@app.route('/api/data', methods=['GET'])
@token_required
def get_messages(current_user):
    messages = Message.query.all()
    output = []
    for msg in messages:
        output.append({
            'id': msg.id,
            'author': msg.author.username,
            'content': msg.content
        })
    return jsonify({'messages': output})


# 3) POST /api/data - Публикация нового сообщения
@app.route('/api/data', methods=['POST'])
@token_required
def post_message(current_user):
    data = request.get_json()
    if not data or not data.get('content'):
        return jsonify({'message': 'Сообщение не может быть пустым'}), 400

    # Защита от XSS
    safe_content = bleach.clean(data['content'])

    new_message = Message(content=safe_content, user_id=current_user.id)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Сообщение опубликовано', 'content': safe_content}), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)