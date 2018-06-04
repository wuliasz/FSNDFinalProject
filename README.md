## Item Catalog App - for Linux Virtual Machine


#### Overview:

This project is the same as the Item Catalog project found here:
https://github.com/wuliasz/ItemCatalog.git

This version has been modified to run in a digital ocean linux environment.


#### URL:
This item catalog can be found here:
http://165.227.211.197/catalog


**WARNING: Chrome and IE browsers have warned me that this site is UNSAFE.** 
But I would assure you that it is only my item catalog that runs here.   
** THE SITE WAS ABANDONED IN 2018 AND I EXPECT THE IP ABOVE TO HAVE BEEN REUSED SINCE THEN **
This IP is to my second digital ocean droplet, created after having problems 
with the first one.  I assume that I've received a recycled IP previously 
owned by some bad players, but, I really don't know that.
I have submitted a request to https://feedback.smartscreen.microsoft.com 
to explicitly label this site as safe. I am nearing my nano-degree completion 
deadline so I would rather not wait for the status to clear before submitting 
the project 


#### SSH Access
Access using user, grader at 165.227.211.197 port 2200 using SSH (I used PuTTY).
SSH Key provided in *Notes to Reviewer* field.


#### Summary of Software Installed
* finger
* Apache2
* Git
* Web Services Gateway Interface (WSGI)
* Python 3
* PIP
* Flask
* Flask HTTPAuth
* SQLAlchemy
* Passlib
* OAuth2Client


#### Summary of Server Configurations Made
* Reset root password.
* Created two new users.
* Defined sudoers
* Forced using SSH.
* Prevented remote root login.
* Changed the default listening port.
* Updated software.
* Set up firewall (deny incoming, allow outgoing, etc.).
* Created directory for applications.
* Clone Item Catalog. 
* Modified localhost python to work on the server, 
  specifically to be called via the WSGI.
* Update Apache Configuation:
	* Specify WSGIPythonPath.
	* Specify server name.
	* Define the Item Catalog WSGI.
	* Specify site configuration:
		*Specify ItemCatalog WSGI file and path.
		*Activated the Item Catalog site.



#### List of Third Party Resources Used
* Digital Ocean Server
* Google OAuth


