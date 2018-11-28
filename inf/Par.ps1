#Conexión a MySQL

function Connect-MySQL([string]$user,[string]$pass,[string]$MySQLHost,[string]$database) { 
  [void][system.reflection.Assembly]::LoadWithPartialName("MySql.Data") 

  $connStr = "server=" + $MySQLHost + ";port=3306;uid=" + $user + ";pwd=" + $pass + ";database="+$database+";Pooling=FALSE" 
  $conn = New-Object MySql.Data.MySqlClient.MySqlConnection($connStr) 
  $conn.Open() 
  return $conn 
} 

function Disconnect-MySQL($conn) {
  $conn.Close()
}

$user = 'root' 
$pass = 'passwordUPC2018' 
$database = 'auditoria' 
$MySQLHost = 'localhost' 

$conn = Connect-MySQL $user $pass $MySQLHost $database

function Execute-MySQLNonQuery($conn, [string]$query) { 
  $command = $conn.CreateCommand()                  # Create command object
  $command.CommandText = $query                     # Load query into object
  $RowsInserted = $command.ExecuteNonQuery()        # Execute command
  $command.Dispose()                                # Dispose of command object
  if ($RowsInserted) { 
    return $RowInserted 
  } else { 
    return $false 
  } 
} 

$StartDate = (get-date)

#Caso 1
function Get-AccountManagement(){
    $queryIni = "Delete from auditoria.usermanagment where id != -1;" 
    $RowsIni = Execute-MySQLNonQuery $conn $queryIni 
    Write-Host $RowsIni "Limpiando Tabla en base de datos"
    $IDs = 4720, 4624
    foreach($ID in $IDs){
        try {Get-WinEvent -FilterHashtable @{LogName="Security";ID=$ID;StartTime=$StartDate.Date.AddDays(-1)} -ErrorAction Stop | Foreach {
        $event = [xml]$_.ToXml()
            if($event)
            {
                $Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
                $CreatorUser = $event.Event.EventData.Data| where "Name" -eq "SubjectUserName" | Select-Object -ExpandProperty '#text'
                $NewUser = $event.Event.EventData.Data | where "Name" -eq "TargetUserName" | Select-Object -ExpandProperty '#text'
                $dc = $event.Event.System.computer
                $query = "INSERT INTO usermanagment (event,server, time, creator,user) VALUES ('$ID','$dc', '$time', '$CreatorUser','$NewUser')" 
                $Rows = Execute-MySQLNonQuery $conn $query 
                Write-Host $Rows "Insertando a la base de datos"
            }
        }
    } catch [Exception]{
                if ($_.Exception -match "No events were found that match the specified selection criteria.") {
            Write-Host "Evento No encontrado";
                     }
        }
    }
}
#Get-AccountManagement

#Caso 2
function Get-LogEvents(){
    $queryIni = "Delete from auditoria.logevents where id != -1;" 
    $RowsIni = Execute-MySQLNonQuery $conn $queryIni 
    Write-Host $RowsIni "Limpiando Tabla en base de datos"
    $IDs = 4624,4647,4625,4778,4779,4800,4801,4802,4803 #4624,4634
    foreach($ID in $IDs){
        try {
        Get-WinEvent -FilterHashtable @{LogName="Security";ID=$ID;StartTime=$StartDate.Date} -ErrorAction Stop | Foreach {
        $event = [xml]$_.ToXml()
        if($event)
            {
            if($ID -eq 4624 -and $event.Event.EventData.Data[8].'#text'.Equals('3'))
                {
                return
                }
            $Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
            $User = $event.Event.EventData.Data | where "Name" -eq "TargetUserName" | Select-Object -ExpandProperty '#text'
            $dc = $event.Event.System.computer
            $query = "INSERT INTO Logevents (event,server, time, user) VALUES ('$ID','$dc', '$time', '$User')" 
            $Rows = Execute-MySQLNonQuery $conn $query 
            Write-Host $Rows "Insertando a la base de datos"
            }
        }
        } catch [Exception]{
                if ($_.Exception -match "No events were found that match the specified selection criteria.") {
            Write-Host "Evento No encontrado";
                     }
        }
    }
}
#Get-LogEvents

#Caso 3
function Get-LastLogon(){
    $queryIni = "Delete from auditoria.lastlogonevent where id != -1;" 
    $RowsIni = Execute-MySQLNonQuery $conn $queryIni 
    Write-Host $RowsIni "Limpiando Tabla en base de datos"
    $currentDate = (get-date)
     $lltIntLimit = $currentDate.ToFileTime()
     $adobjroot = [adsi]''
     $objstalesearcher = New-Object System.DirectoryServices.DirectorySearcher($adobjroot)
     $objstalesearcher.filter = "(&(objectCategory=person)(objectClass=user)(lastLogonTimeStamp<=" + $lltIntLimit + "))"

    $users = $objstalesearcher.findall() | select `
     @{e={$_.properties.cn};n='Display Name'},`
     @{e={$_.properties.samaccountname};n='Username'},`
     @{e={[datetime]::FromFileTimeUtc([int64]$_.properties.lastlogontimestamp[0])};n='Last Logon'},`
     @{e={[string]$adspath=$_.properties.adspath;$account=[ADSI]$adspath;$account.psbase.invokeget('AccountDisabled')};n='Account Is Disabled'}

     foreach($user in $users){
        $lastLog = $user | Select-Object -ExpandProperty 'Last Logon'
        $restaFechas = (Get-Date).Subtract($lastLog) | Select-Object -ExpandProperty Days
            if($restaFechas -eq 90){
            Disable-ADAccount -Identity ($user | Select-Object -ExpandProperty 'Username')}
        $displayname = $user.'Display Name'
        $username = $user.Username
        $lastl = $user.'Last Logon'
        $aid = $user.'Account Is Disabled'
        $query = "INSERT INTO lastlogonevent (displayname,username, lastlogon,days, disable) VALUES ('$displayname','$username','$lastl','$restaFechas','$aid')" 
        $Rows = Execute-MySQLNonQuery $conn $query 
        Write-Host $Rows "Insertando a la base de datos"
    }
}
Get-LastLogon