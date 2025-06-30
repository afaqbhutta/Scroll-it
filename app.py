from flask import Flask, request, render_template

app = Flask(__name__)
entries = []  # This will be lost when the app restarts

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        movie = request.form['movie']
        entries.append({'name': name, 'movie': movie})
    return render_template('home.html', entries=entries)

if __name__ == '__main__':
    app.run(debug=True)
