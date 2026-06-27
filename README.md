# Entra ID Apps Report

This solution gathers information about App Registrations and Service Principals of an Entra ID tenant and shows the information in a Power BI report.

There’s also some extra information like expiring credentials, permissions granted to the apps, and EXO policies tied to these apps.

## Features

* Power BI report with information of App Registrations and Service Principals.
* Email notifications of expiring credentials to application owners (see [email notifications](https://github.com/jesusfer/entraid-apps-report/wiki/Email-Notifications)).
* EXO Application Access Policies related to the tenant's service principals.
* EXO management role assignments granted to the tenant's service principals, either directly or through a role group. Roles are categorized as app-only roles (the `Application <permission>` roles of the RBAC for Applications model) or other.

### Planned features

* _Nothing planned at the moment._

## Permissions

The runbooks authenticate to Exchange Online with an app registration (app-only,
certificate based). The Exchange Online management roles below must be assigned to
that app registration so the runbooks can run their cmdlets:

Cmdlet | Runbook | Required EXO management role
-|-|-
`Get-ApplicationAccessPolicy` | `exo-policies.ps1` | View-Only Configuration
`Get-ServicePrincipal` | `exo-policies.ps1` | Role Management
`Get-ManagementRoleAssignment` | `exo-policies.ps1` | Role Management

> The `Get-ServicePrincipal` and `Get-ManagementRoleAssignment` cmdlets used to
> collect role assignments are part of the Role Management role, so this role
> must be assigned to the app registration in addition to View-Only Configuration.

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
