

What is MiniTwit?

      A SQLite and Flask powered twitter clone

    ~ How do I use it?

      1. edit the configuration in the minitwit.py file or
         export an MINITWIT_SETTINGS environment variable
         pointing to a configuration file.

      2. install the app from the root of the project directory

         pip install --editable .

      3. tell flask about the right application:

         export FLASK_APP=minitwit

      4. fire up a shell and run this:

         flask initdb

	  5. Initialize the db with dummy data (optional)
		 flask populatedb

      6. now you can run minitwit:

         flask run

         the application will greet you on
         http://localhost:5000/
