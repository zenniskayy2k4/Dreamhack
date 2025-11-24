from flask import Flask, render_template, send_from_directory, abort

app = Flask(__name__, static_folder="static", template_folder="templates")

@app.route("/")
def index():
    return render_template(
        "index.html",
        image_filename="image.gif",  
        song_filename="song.mp3",   
    )

@app.route("/song")
def song():
    try:
        return send_from_directory("song", "song.mp3")
    except FileNotFoundError:
        abort(404)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5225)
