# Azure Sentinel and Google Alert Center Integration

This ARM template will deploy a function app that will pull alerts from Google alert center using API and push to a custom table in Sentinel named "GWorkspace_AlertCenter_CL"
This requires impersonating an admin account using credentials file, with domain wide delegation enabled.

### Pre-reqs
* Workspace ID: Workspace id of the azure sentinel.
* Workspace Key: Workspace key of the azure sentinel.
* Impersonation Account: The account to impersonate.
* Credentials File Name: The file name that holds the credentials.

### Process to add the credentials file 
Import the function app in the Visual Studio and create the credentials file, then redeploy the app.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Ffrozenstrawberries%2Fautomations%2Fmain%2FAzure%2FARM%20Templates%2FSentinel%20and%20Google%20Alert%20Center%20Integration%2FARM_template.json%26api-version%3D6.0)