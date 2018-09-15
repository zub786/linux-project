# Catalog App
 This is an application in which a walk-in (Un-Registered) user can view categories and there items. A new user can be resgister and login with google plus and facebook, so that he/she can add categories and items in it and modify them as well.
Remember, a logged in user cannot modify the items of a categorie added by another user.

## Prerequisites & Getting Started

	1. First you will have to install virtual box
	2. Then install tool to working with virtual box here we are using vagrant
	3. If you have not started you virtual machine yet go to vagrant folder for which you want to create virtual machine and open git bash and execute vagrant up command to on the virtual machine
	4. After starting virtual machine use vagrant ssh command to login on virtual machine
	5. After Login, change the present working directory by using this command [ "cd /vagrant/catalog" ]
	6. After executing above mentioned command execute the models.py file to generate database with tables for this use this command [ "python models.py" ]
	7. After executing above mentioned command execute the application.py file to run the application for this use this command [ "python application.py" ]



## How to use application
	1. On the left pane, all available categories are showing
	2. On the right pane, all latest items of the categories are showing
	3. If user is logged in he/she can do everything means Create, Update and Delete
	4. But, Logged out user can only view the categories and there items by clicking on them.
	5. For furthur query, you can contact at Email: muhammad.zubair@arbisoft.pk