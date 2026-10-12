样本ID：SQLI-005；输入包：SQLI-005-P2；版本：v2
业务场景：用户注册、登录与修改密码
来源引用：内部台账同ID；原始路径与提交号由人工追溯。
审计范围：SQL注入
参数与入口：注册POST submit/username/password/re_password；登录POST login_user/login_password；改密POST submit/current_password/password/re_password；Cookie Auth；SESSION username
必要条件：三个独立HTTP阶段共享同一数据库与登录会话；审计全部步骤，不假定数据库或会话中的值自动可信。
已知限制：依赖旧mysql_*接口、数据库users表及本地配置；不得部署审计片段替代完整靶场；Location/refresh调用前已有输出，运行行为受PHP输出缓冲影响。
调用与依赖关系：
- A写入users.username/password
- B查询users后把数据库返回的username写入SESSION
- C读取SESSION.username并生成UPDATE
- D提供A/B/C的数据库连接

关联片段 SQLI-005-B（登录读取与会话赋值），行号从其代码块第一行起计。
```php
<html>
<head>
</head>
<body bgcolor="#000000">
<font size="3" color="#FFFF00">
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a>
</div>
<?PHP

session_start();
//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");




function sqllogin(){

   $username = mysql_real_escape_string($_POST["login_user"]);
   $password = mysql_real_escape_string($_POST["login_password"]);
   $sql = "SELECT * FROM users WHERE username='$username' and password='$password'";
//$sql = "SELECT COUNT(*) FROM users WHERE username='$username' and password='$password'";
   $res = mysql_query($sql) or die('You tried to be real smart, Try harder!!!! :( ');
   $row = mysql_fetch_row($res);
	//print_r($row) ;
   if ($row[1]) {
			return $row[1];
   } else {
      		return 0;
   }

}






$login = sqllogin();
if (!$login== 0) 
{
	$_SESSION["username"] = $login;
	setcookie("Auth", 1, time()+3600);  /* expire in 15 Minutes */
	header('Location: logged-in.php');
} 
else
{
?>
<tr><td colspan="2" style="text-align:center;"><br/><p style="color:#FF0000;">
<center>
<img src="../images/slap1.jpg">
</center>
</p></td></tr>
<?PHP
} 
?>






</body>
</html>
```

关联片段 SQLI-005-C（修改密码及退出），行号从其代码块第一行起计。
```php
<html>
<head>
</head>
<body bgcolor="#000000">
<?PHP
session_start();
if (!isset($_COOKIE["Auth"]))
{
	if (!isset($_SESSION["username"])) 
	{
   		header('Location: index.php');
	}
	header('Location: index.php');
}
?>
<div align="right">
<a style="font-size:.8em;color:#FFFF00" href='index.php'><img src="../images/Home.png" height='45'; width='45'></br>HOME</a>
</div>
<?php

//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");



if (isset($_POST['submit']))
{
	
	
	# Validating the user input........
	$username= $_SESSION["username"];
	$curr_pass= mysql_real_escape_string($_POST['current_password']);
	$pass= mysql_real_escape_string($_POST['password']);
	$re_pass= mysql_real_escape_string($_POST['re_password']);
	
	if($pass==$re_pass)
	{	
		$sql = "UPDATE users SET PASSWORD='$pass' where username='$username' and password='$curr_pass' ";
		$res = mysql_query($sql) or die('You tried to be smart, Try harder!!!! :( ');
		$row = mysql_affected_rows();
		echo '<font size="3" color="#FFFF00">';
		echo '<center>';
		if($row==1)
		{
			echo "Password successfully updated";
	
		}
		else
		{
			header('Location: failed.php');
			//echo 'You tried to be smart, Try harder!!!! :( ';
		}
	}
	else
	{
		echo '<font size="5" color="#FFFF00"><center>';
		echo "Make sure New Password and Retype Password fields have same value";
		header('refresh:2, url=index.php');
	}
}
?>
<?php
if(isset($_POST['submit1']))
{
	session_destroy();
	setcookie('Auth', 1 , time()-3600);
	header ('Location: index.php');
}
?>
</center>  
</body>
</html>
```

关联片段 SQLI-005-D（共享数据库连接），行号从其代码块第一行起计。
```php
<?php

//including the Mysql connect parameters.
include("../sql-connections/db-creds.inc");
@error_reporting(0);
@$con = mysql_connect($host,$dbuser,$dbpass);
// Check connection
if (!$con)
{
    echo "Failed to connect to MySQL: " . mysql_error();
}


    @mysql_select_db($dbname,$con) or die ( "Unable to connect to the database: $dbname");






$sql_connect = "SQL Connect included";
############################################
# For Less-24
$form_title_in="Please Login to Continue";
$form_title_ns="New User";
$feedback_title_ns="New User";
$form_title_ns= "Less-24";

############################################
# For Challenge series--- Randomizing the Table names.

?>




 
```

期望输出：记录本包证据和未提供的依赖，不把缺失片段当不存在；使用片段ID及局部行号定位。收到该父样本全部输入包后，综合调用关系、存储与会话来源、权限条件形成结论。这里只提供代码输入，完整审计Prompt由组2设计。
