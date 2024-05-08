# Entra ID Apps Report

This solution gathers information about App Registrations and Service Principals of an Entra ID tenant and shows the information in a Power BI report.

There’s also some extra information like expiring credentials, permissions granted to the apps, and EXO policies tied to these apps.

## Features

* Power BI report with information of App Registrations and Service Principals.
* Email notifications of expiring credentials to application owners (see [email notifications](https://github.com/jesusfer/entraid-apps-report/wiki/Email-Notifications)).
* EXO Application Access Policies related to the tenant's service principals.

### Planned features

* Information about EXO Role assignments assigned to service principals.

## Solution diagram

The solution uses these Azure resources:

Resource|Reason
-|-
Automation Account | Used to execute the runbooks that gather information from Entra ID
Storage Account (tables) | Used to store the information about apps, service principals and sent notifications.

A diagram to show the architecture:

![solution-diagram](https://github.com/jesusfer/entraid-apps-report/wiki/img/solution-diagram.png)

## Setup

The deployment consists of several steps:

1. Create all the Azure resources.
2. Set up variables in the Automation account.
3. Schedule the runbooks.
4. Connect and publish the report.

Head over to the [install docs](https://github.com/jesusfer/entraid-apps-report/wiki/Installation-instructions) to get started.

## More information

More information available here:

* [Detailed data model](https://github.com/jesusfer/entraid-apps-report/wiki/Data-model)
* [Configuration variables](https://github.com/jesusfer/entraid-apps-report/wiki/Installation-instructions#variables)
