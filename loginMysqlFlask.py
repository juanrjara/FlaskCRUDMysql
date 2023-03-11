from flask import Flask, jsonify, request
import hashlib
import jwt
import datetime
import mysql.connector
import time
import requests

# Definimos el secret_key para los tokens jwt - RECOMIENDO USAR os.environ para obtener una enviroment variable o en su defecto usar un archivo config.ini con el secret_key.
secret_key = '$3cr3t04app$'
# Creamos la instancia de Flask
app = Flask(__name__)

# Conectamos a la base de datos - RECOMIENDO USAR os.environ para obtener las enviroment variables o en su defecto usar un archivo config.ini con el user y password al menos.
db = mysql.connector.connect(
    host="localhost",
    user="us3r4pp",
    password="t3st4ser$",
    database="dbtest"
)

# Definimos una ruta para el endpoint loginApp con el método POST
@app.route('/loginApp', methods=['POST'])
def login():
    # Obtenemos los datos de usuario y contraseña enviados en el body del request
    user = request.json.get('user', None)
    password = request.json.get('password', None)

    # Si no se envió usuario o contraseña, devolvemos un error
    if not user or not password:
        return jsonify({'error': 'missing_data'})

    # Encriptamos la contraseña ingresada por el usuario
    encrypted_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    # Obtenemos un cursor para ejecutar consultas en la base de datos
    cursor = db.cursor()

    # Ejecutamos la consulta para obtener el usuario y su contraseña encriptada
    query = "SELECT user, password FROM users WHERE user = %s"
    cursor.execute(query, (user,))

    # Obtenemos el resultado de la consulta
    result = cursor.fetchone()

    # Si el usuario no existe en la base de datos, devolvemos un error
    if not result:
        return jsonify({'error': 'user_not_found'})

    # Si la contraseña encriptada ingresada por el usuario no coincide con la almacenada en la base de datos, devolvemos un error
    if result[1] != encrypted_password:
        return jsonify({'error': 'incorrect_password'})

    # Generamos un token JWT con una expiración de 2 horas
    token = jwt.encode({'user': user, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}, secret_key, algorithm='HS256')

    # Devolvemos la respuesta con el token JWT
    return jsonify({'response': 'yes', 'token': token})

# Endpoint to validate token and fetch a joke
@app.route('/getJoke', methods=['GET'])
def getJoke():
    # Get JWT token from header
    bearer_token = request.headers.get('Authorization')
    if bearer_token:
        token = bearer_token.split()[1]
        try:
            # Validate JWT token
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            if payload:
                # Check if token has expired
                if payload.get('exp') and payload.get('exp') < time.time():
                    return jsonify(response='expired_token')
                # Fetch joke based on topic
                topic = request.json.get('topic', None)
                joke_response = requests.get(f'https://api.chucknorris.io/jokes/search?query={topic}')
                joke_json = joke_response.json()
                joke = joke_json['result'][0]['value']
                return jsonify(response='yes', joke=joke)
        except jwt.ExpiredSignatureError:
            return jsonify(response='expired_token')
        except (jwt.InvalidTokenError, IndexError, KeyError):
            pass
    return jsonify(response='error')
# Ejecutamos la aplicación en el puerto 5000
if __name__ == '__main__':
    app.run(debug=True)
