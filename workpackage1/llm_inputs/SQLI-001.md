样本 ID：SQLI-001
来源引用：内部台账同 ID（本审计输入隐藏原始关卡名称；完整追溯信息由评估人员保管）
语言：PHP
审计关注类型：SQL注入
入口：顶层请求处理逻辑
请求参数：GET: id
调用及输出关系：包含连接文件后，在顶层请求处理中读取参数、构造并执行查询，直接输出结果或错误。连接实现另存 context/sqli-connect.php。
外部依赖：sql-connections/sql-connect.php；db-creds.inc；security 数据库及 users 表
已知限制：审计片段不能独立部署；mysql_* 接口需要兼容运行环境；不得把 PHP 接口错误当作误报。
行号约定：报告 normalized_samples/SQLI-001.php 的 1 起始行号；人工使用 line_maps/SQLI-001.csv 回溯。

代码片段：
```php
<?php
//including the Mysql connect parameters.
include("../sql-connections/sql-connect.php");
error_reporting(0);
// take the variables 
if(isset($_GET['id']))
{
$id=$_GET['id'];
//logging the connection parameters to a file for analysis.
$fp=fopen('result.txt','a');
fwrite($fp,'ID:'.$id."\n");
fclose($fp);
// connectivity 
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result=mysql_query($sql);
$row = mysql_fetch_array($result);
	if($row)
	{
  	echo "<font size='5' color= '#99FF00'>";
  	echo 'Your Login name:'. $row['username'];
  	echo "<br>";
  	echo 'Your Password:' .$row['password'];
  	echo "</font>";
  	}
	else 
	{
	echo '<font color= "#FFFF00">';
	print_r(mysql_error());
	echo "</font>";  
	}
}
	else { echo "Please input the ID as parameter with numeric value";}
?>
```

期望输出：判断存在相关漏洞、不存在所关注漏洞，或证据不足；给出输入来源、关键处理、危险操作、代码行号、成立条件和需要补充的证据。不能把危险函数名称本身当作漏洞成立证据。此文件是代码输入模板实例，不代替提示词组的完整审计 Prompt。
