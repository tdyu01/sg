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
function Get-changepassword(){
    $query2 = "delete from changepassword"
    $Rows2 = Execute-MySQLNonQuery $conn $query2
    Write-Host $Rows2 " cleaned database"
    try {
    Get-WinEvent -FilterHashtable @{LogName="Security";ID=4724;StartTime=$StartDate.Date} -ErrorAction Stop | Foreach {
        $sucess = $_.KeywordsDisplayNames
        $event = [xml]$_.ToXml()
        if($event -or ((Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S") -lt (Get-Date).AddHours(9)) -or ((Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S") -gt (Get-Date).AddHours(18)))
        {
            $Time = Get-Date $_.TimeCreated -UFormat "%Y-%m-%d %H:%M:%S"
            $Domain = $event.Event.EventData.Data| where "Name" -eq "TargetDomainName" | Select-Object -ExpandProperty '#text'
            $User = $event.Event.EventData.Data | where "Name" -eq "TargetUserName" | Select-Object -ExpandProperty '#text'
            $dc = $event.Event.System.Computer
            $vsuccess = @()
            if(($sucess -eq "Audit Success").Count -eq '0'){
                $vsuccess = "Insatisfactorio"
                }
            else{
                $vsuccess = "Satisfactorio"
            }

            $query = "INSERT INTO changepassword (user,domain,computer, time, sucess) VALUES ('$user','$domain', '$dc' ,'$time', '$Vsuccess')" 
            $Rows = Execute-MySQLNonQuery $conn $query 
            Write-Host $Rows " inserted into database"

        }
        }} catch [Exception]{
                    if ($_.Exception -match "No events were found that match the specified selection criteria.") {
                Write-Host "Evento No encontrado";
                         }
    }
}
Get-changepassword