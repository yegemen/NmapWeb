# NmapWeb

It is an application developed to use the nmap tool from the web interface. 

## Installation

- The nmap tool must be installed on the system.

- for Linux:

  `sudo apt-get install nmap`

- for Windows: 

  *Download and install the setup file for windows from the nmap website. *

- Installing necessary python modules: 

  `pip install -r requirements.txt`

- To create the database and tables, run the following commands. (python or python3) 

  `python manage.py makemigrations`

  `python manage.py migrate`

## Usage
- Run this command. (python or python3) 

  `python manage.py runserver`

- You can use the application by entering the address http://127.0.0.1:8000/
