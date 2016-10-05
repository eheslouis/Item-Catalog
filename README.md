# Udacity FSND Project 3 - Item Catalog

## Overview
Udacity FSND Project 3 - Item Catalog. This project allows for a list of items to be stored within categories. Visitors can login through the Google+ OAuth API.

## Features
- Google+ Authentication
- Facebook Authentication
- Registered users can create, edit and delete items 
- Users can only edit and delete their own items

## Installation
* You will need to install the pre-configured Vagrant VM for the Full Stack Foundations Course from Udacity. For instructions on how to do this, visit [https://www.udacity.com/wiki/ud088-nd/vagrant]
(https://www.udacity.com/wiki/ud088-nd/vagrant)

## Usage
To reset the database:

- Run python database_setup.py. 
- Run lotOfItem.py to populate the database

To run the project:

- start the Vagrant VM
- Run python application.py from the Vagrant machine
- Visit http://localhost:8000/