# Service principal permissions

## oauth2PermissionGrants

> Delegated permission grants authorizing this service principal to access an API on behalf of a signed-in user. Read-only. Nullable.

* Solo muestra grants de permisos delegados para los que un admin o usuarios han dado su consentimiento.
* Solo tiene sentido para aplicaciones que consumen otras APIs

* consentType==AllPrincipals -> admin grants
  * cuáles? -> scope[]
  * app? -> resourceId

* consentType==Principal -> individual
  * quién? -> principalId
  * cuáles -> scope[]
    *app? -> resourceId

## appRoleAssignedTo

> App role assignments for this app or service, granted to users, groups, and other service principals. **Supports $expand**.

* Si el app reg/declara permisos de aplicación (appRoles), esta es la lista de usuarios, grupos y aplicaciones que tienen esos permisos de aplicación.
* Si el principal es ServicePrincipal entonces aparecen los admin grants para permisos de aplicación y sus aplicaciones cliente.
* Si appRoleId==00000000-0000-0000-0000-000000000000 -> Default access
  * principalId -> objectId del principal
  * principalType -> User|ServicePrincipal|Group
  * resourceId -> API (self)

## appRoleAssignments

> App role assignment for another app or service, granted to this service principal. **Supports $expand**.

* Si esta aplicación consume permisos de aplicación, aquí aparecen los permisos para los que se ha hecho un admin grant.

* appRoleAssignments
  * appRoleId -> id del permiso de aplicación
  * principalId -> quién tiene el permiso (Self)
  * resourceId -> Object Id del service principal que declara el permiso

## Conclusiones

* No hay colisión entre appRoleAssignedTo y appRoleAssignments. El primero se usa para mostrar la lista de principals que consumen app roles de ese service principal y el segundo se usa para obtener la lista de app roles que consume el service principal y para los que tiene admin grant.
* Si no hay admin grant no hay assignment.

## Ejemplo

appreg que declara permisos delegados y de aplicación
appid 4b0a3ae8-2f32-4f30-be47-37776ca0d39d
objid f8fa5f8a-e681-48ae-ad9b-a3a81b819429
sp que declara
objid f6982e6a-2065-47b0-9ab8-be533e0ffe31

sp que declara, roles asignados a usuarios/grupos
adele x1 + app roles client x2
-> appRoleAssignedTo

appreg que usa permisos delegados y de aplicación
appid aa29efed-58e7-4651-a15f-7a6d68557a89
objid a19778a0-fa27-4e80-9ecc-52f4c98944fe
sp que consume
77ad36cd-bda9-45ce-bb3d-447de5695952

sp que consume, roles asignados
group + usuario con default access
-> appRoleAssignedTo
-> appRoleId==00000000-0000-0000-0000-000000000000 -> Default access

sp que consume, grants
-> oauth2PermissionGrants
-> permisos delegados

-> consentType==AllPrincipals -> admin grants
    cuáles? -> scope[]
    app? -> resourceId
-> consentType==Principal -> individual
    quién? -> principalId
    cuáles -> scope[]
    app? -> resourceId

sp que consume, grants de aplicación?
-> appRoleAssignments
    appRoleId -> id del permiso de aplicación
    principalId -> quién tiene el permiso
    resourceId -> app que declara el permiso

app que consume, permisos que quiere tener
-> requiredResourceAccess
-> por cada api (resourceAppId), los permisos que quiere tener, resourceAccess[]
    type==Role aplicación
    type==Scope delegados
