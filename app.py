from flask import Flask, render_template, request, jsonify
import mysql.connector
from bcrypt import hashpw, gensalt, checkpw
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure Flask for production
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    PREFERRED_URL_SCHEME='https'
)


# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DATABASE_HOST'),
        user=os.getenv('DATABASE_USER'),
        password=os.getenv('DATABASE_PASSWORD'),
        database=os.getenv('DATABASE_NAME')
    )


@app.route('/')
def index():
    return render_template('signup.html')


@app.route('/reset-password')
def reset_password():
    return render_template('reset-password.html')


@app.route('/reset')
def reset():
    return render_template('reset.html')


@app.route('/get_security_questions', methods=['GET'])
def get_security_questions():
    questions = [
        {"value": "pet", "text": "What is the name of your first pet?"},
        {"value": "mother_maiden", "text": "What is your mother's maiden name?"},
        {"value": "city_birth", "text": "In which city were you born?"},
        {"value": "school", "text": "What was the name of your first school?"},
        {"value": "favorite_teacher", "text": "Who was your favorite teacher?"}
    ]
    return jsonify(questions)


@app.route('/verify_security_questions', methods=['POST'])
def verify_security_questions():
    data = request.json
    email = data['email']
    answers = data['answers']

    con = get_db_connection()
    cursor = con.cursor(dictionary=True)

    cursor.execute("SELECT SecurityQuestions FROM UserProfiles WHERE Email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()
    con.close()

    if result:
        stored_questions = result['SecurityQuestions'].split(';')
        for i, answer in enumerate(answers):
            stored_answer = stored_questions[i].encode('utf-8')
            if not checkpw(answer.encode('utf-8'), stored_answer):
                return jsonify({"success": False}), 401

        return jsonify({"success": True})
    else:
        return jsonify({"success": False}), 404


@app.route('/submit', methods=['POST'])
def submit():
    email = request.form['email']
    password = request.form['password']
    sec_question1 = request.form['sec_question1']
    sec_answer1 = request.form['sec_answer1']
    sec_question2 = request.form['sec_question2']
    sec_answer2 = request.form['sec_answer2']
    sec_question3 = request.form['sec_question3']
    sec_answer3 = request.form['sec_answer3']

    # Hashing the password and security answers
    hashed_password = hashpw(password.encode('utf-8'), gensalt())
    hashed_answer1 = hashpw(sec_answer1.encode('utf-8'), gensalt())
    hashed_answer2 = hashpw(sec_answer2.encode('utf-8'), gensalt())
    hashed_answer3 = hashpw(sec_answer3.encode('utf-8'), gensalt())

    # Combine security questions and hashed answers
    security_data = f"{sec_question1}:{hashed_answer1.decode('utf-8')};{sec_question2}:{hashed_answer2.decode('utf-8')};{sec_question3}:{hashed_answer3.decode('utf-8')}"

    # Insert user data into the database
    con = get_db_connection()
    cursor = con.cursor()
    try:
        cursor.execute("INSERT INTO UserProfiles (Email, Password, SecurityQuestions) VALUES (%s, %s, %s)",
                       (email, hashed_password.decode('utf-8'), security_data))
        con.commit()
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        con.rollback()
        return "An error occurred while processing your request. Please try again later.", 500
    finally:
        cursor.close()
        con.close()

    return "Form submitted successfully!"


if __name__ == '__main__':
    app.run(debug=True)
