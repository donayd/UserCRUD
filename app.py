from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:password@127.0.0.1:3306/fourgenusers'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

if  __name__ == '__main__':  
     app.run(debug=True)


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    identification = db.Column(db.Integer)
    forename = db.Column(db.String(20))
    surname = db.Column(db.String(20))
    age = db.Column(db.Integer)

    def create(self):
      db.session.add(self)
      db.session.commit()
      return self
    def __init__(self,identification,forename,surname,age):
        self.identification = identification
        self.forename = forename
        self.surname = surname
        self.age = age
    def __repr__(self):
        return '' % self.id
db.create_all()


class UserSchema(ModelSchema):
    class Meta(ModelSchema.Meta):
        model = User
        sqla_session = db.session
    id = fields.Number(dump_only=True)
    identification = fields.Number(required=True)
    forename = fields.String(required=True)
    surname = fields.String(required=True)
    age = fields.Number(required=True)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator

@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    
    return jsonify({'message': 'registeration successfully'})

@app.route('/login', methods=['POST'])  
def login_user(): 
    auth = request.authorization   
    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'Authentication': 'login required"'})    
    user = Users.query.filter_by(name=auth.username).first()   
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token' : token}) 
    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/users', methods = ['GET'])
def index():
    get_users = User.query.all()
    user_schema = UserSchema(many=True)
    users = user_schema.dump(get_users)
    return make_response(jsonify({"user": users}))


@app.route('/users', methods = ['POST'])
@token_required
def create_user():
    data = request.get_json()
    user_schema = UserSchema()
    user = user_schema.load(data)
    result = user_schema.dump(user.create())
    return make_response(jsonify({"user": result}), 200)


@app.route('/users/<id>', methods = ['PUT'])
@token_required
def update_user_by_id(id):
    data = request.get_json()
    get_user = User.query.get(id)
    if data.get('identification'):
        get_user.identification = data['identification']
    if data.get('forename'):
        get_user.forename = data['forename']
    if data.get('surname'):
        get_user.surname = data['surname']
    if data.get('age'):
        get_user.age= data['age']    
    db.session.add(get_user)
    db.session.commit()
    user_schema = UserSchema(only=['id', 'identification', 'forename', 'surname', 'age'])
    user = user_schema.dump(get_user)
    return make_response(jsonify({"user": user}))


@app.route('/users/<id>', methods = ['DELETE'])
@token_required
def delete_user_by_id(id):
    get_user = User.query.get(id)
    db.session.delete(get_user)
    db.session.commit()
    return make_response(jsonify({'message': 'User Deleted'}),204)