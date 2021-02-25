from app import app
import os
print(os.environ)

app.run(debug=True, host='0.0.0.0', port=5000)
