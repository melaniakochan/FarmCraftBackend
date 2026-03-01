# FarmCraftBackend
Our architecture:
<img width="1003" height="508" alt="image" src="https://github.com/user-attachments/assets/82156ff2-05bf-4ae9-bcee-ee144900c788" />

Soon this will be deployed on AWS. For now, check it out locally!

Make sure you have aws sam tool installed and npm, 

Clone this reposity and the front end repository into two folders.

In the backend folder, do sam local start-api

This will spit out a localhost with the port. Save this and use it for your front end. 

Edit the env.example file to env.local, and set the api_base_url to the localhost your backend spit out.

In the frontend folder, do npm install, then npm dev run. 

Then click on the local host link that that gives you, and youre ready to use FarmCraft!! Happy Farming :-)

