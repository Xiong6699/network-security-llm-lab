样本ID：AUTH-001；输入包：AUTH-001-P2；版本：v2
业务场景：用户管理页面与数据接口
来源引用：内部台账同ID；原始路径与提交号由人工追溯。
审计范围：权限越权
参数与入口：页面GET；列表接口GET；更新接口POST JSON{id,first_name,surname}；会话用户；security配置
必要条件：业务约定：仅admin可读取或修改所有用户资料。页面被包含的角色检查与security配置相关：low版本无额外执行语句；medium/high/impossible版本有角色检查。源码中的等级分支是实际控制条件，不作为最终标签。
已知限制：普通用户与admin、匿名及不同security配置需要分别验证；页面授权不能替代独立接口授权；SQL拼接和DOM输出问题可另记录，本样本主要评估权限一致性。
调用与依赖关系：
- A启动会话并包含页面角色检查C
- A输出B，B调用D与E
- D/E是独立HTTP入口，不经过A的页面流程
- F定义实际身份与security读取
- G控制菜单可见性并输出A的page.body
- 同一个AUTH-001跨P1/P2/P3综合判定，不能按片数当漏洞数

关联片段 AUTH-001-D（读取所有用户资料接口），行号从其代码块第一行起计。
```php
<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
On high and impossible, only the admin is allowed to retrieve the data.
*/
if ((dvwaSecurityLevelGet() == "high" || dvwaSecurityLevelGet() == "impossible") && dvwaCurrentUser() != "admin") {
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	exit;
}

$query  = "SELECT user_id, first_name, last_name FROM users";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

$guestbook = ''; 
$users = array();

while ($row = mysqli_fetch_row($result) ) { 
	if( dvwaSecurityLevelGet() == 'impossible' ) { 
		$user_id = $row[0];
		$first_name = htmlspecialchars( $row[1] );
		$surname = htmlspecialchars( $row[2] );
	} else {
		$user_id = $row[0];
		$first_name = $row[1];
		$surname = $row[2];
	}   

	$user = array (
					"user_id" => $user_id,
					"first_name" => $first_name,
					"surname" => $surname
				);
	$users[] = $user;
}

print json_encode ($users);
exit;
?>
```

关联片段 AUTH-001-E（修改指定用户资料接口），行号从其代码块第一行起计。
```php
<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
On impossible only the admin is allowed to retrieve the data.
*/

if (dvwaSecurityLevelGet() == "impossible" && dvwaCurrentUser() != "admin") {
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	exit;
}

if ($_SERVER['REQUEST_METHOD'] != "POST") {
	$result = array (
						"result" => "fail",
						"error" => "Only POST requests are accepted"
					);
	echo json_encode($result);
	exit;
}

try {
	$json = file_get_contents('php://input');
	$data = json_decode($json);
	if (is_null ($data)) {
		$result = array (
							"result" => "fail",
							"error" => 'Invalid format, expecting "{id: {user ID}, first_name: "{first name}", surname: "{surname}"}'

						);
		echo json_encode($result);
		exit;
	}
} catch (Exception $e) {
	$result = array (
						"result" => "fail",
						"error" => 'Invalid format, expecting \"{id: {user ID}, first_name: "{first name}", surname: "{surname}\"}'

					);
	echo json_encode($result);
	exit;
}

$query = "UPDATE users SET first_name = '" . $data->first_name . "', last_name = '" .  $data->surname . "' where user_id = " . $data->id . "";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

print json_encode (array ("result" => "ok"));
exit;
?>
```

关联片段 AUTH-001-F（会话、身份与配置函数），行号从其代码块第一行起计。
```php
<?php
function &dvwaSessionGrab() {
	if( !isset( $_SESSION[ 'dvwa' ] ) ) {
		$_SESSION[ 'dvwa' ] = array();
	}
	return $_SESSION[ 'dvwa' ];
}
function dvwaPageStartup( $pActions ) {
	if (in_array('authenticated', $pActions)) {
		if( !dvwaIsLoggedIn()) {
			dvwaRedirect( DVWA_WEB_PAGE_TO_ROOT . 'login.php' );
		}
	}
}
function dvwaIsLoggedIn() {
	global $_DVWA;

	if (array_key_exists("disable_authentication", $_DVWA) && $_DVWA['disable_authentication']) {
		return true;
	}
	$dvwaSession =& dvwaSessionGrab();
	return isset( $dvwaSession[ 'username' ] );
}
function dvwaCurrentUser() {
	$dvwaSession =& dvwaSessionGrab();
	return ( isset( $dvwaSession[ 'username' ]) ? $dvwaSession[ 'username' ] : 'Unknown') ;
}
function dvwaSecurityLevelGet() {
	global $_DVWA;

	// If there is a security cookie, that takes priority.
	if (isset($_COOKIE['security'])) {
		return $_COOKIE[ 'security' ];
	}

	// If not, check to see if authentication is disabled, if it is, use
	// the default security level.
	if (array_key_exists("disable_authentication", $_DVWA) && $_DVWA['disable_authentication']) {
		return $_DVWA[ 'default_security_level' ];
	}

	// Worse case, set the level to impossible.
	return 'impossible';
}
?>
```

期望输出：记录本包证据和未提供的依赖，不把缺失片段当不存在；使用片段ID及局部行号定位。收到该父样本全部输入包后，综合调用关系、存储与会话来源、权限条件形成结论。这里只提供代码输入，完整审计Prompt由组2设计。
