## Setting up Falco account in Salesforce
1. Log in to Salesforce as an Administrator
2. Navigate to the Setup menu
3. Navigate to Administration -> Users and set up a new user for Falco
4. Make sure the user License is *Salesforce* and the profile is *Minimum Access - Salesforce*

5. Navigate to Administration -> Permission Sets, click *New* and give the profile a label and API name
   
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/af42a6af-be99-4d46-a3bf-750754b600b3)

5. In the Permission Set settings, type *View Real-Time Event Monitoring Data* in the Find Settings box
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/31346b69-5617-46ee-9ccc-84b54d1b19cf)

6. Edit the System Permissions and click the checkbox next to *View Real-Time Event Monitoring Data*
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/dca16f2f-43a7-474b-bcd5-5add892ee75d)
7. Click Save

8. Click on *Permission Set Groups*
9. Click on *New Permission Set Group*
10. Enter a label and API name for Falco
11. Click on Permissions Sets in Group
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/36836ad1-f001-4c72-b8a2-ab259b8beaf9)
11. Add FalcoPermissionSet into the Group
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/0f951c66-2266-4fed-bef0-81bfc41f3801)
12. Browse back to the Permission Set Group and click *Manage Assignments*
![image](https://github.com/an1245/falco-plugin-salesforce/assets/127995147/2922cbbb-971d-4708-b241-e340c8d782e8)
13. Add user Falco into the PermissionSetGroup

