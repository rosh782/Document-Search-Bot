ADMIN_SECRET_KEY = 'RK-123'
SQLALCHEMY_DATABASE_URI = 'sqlite:///default.db'
UPLOAD_FOLDER = 'uploads/'
TEXTFILE_FOLDER = 'textfiles/'
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}
SQLALCHEMY_BINDS = {
    'secondary': 'sqlite:///secondary.db',  # Second database
    'primary': 'sqlite:///primary.db'
}
