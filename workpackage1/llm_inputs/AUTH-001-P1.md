样本ID：AUTH-001；输入包：AUTH-001-P1；版本：v2
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

关联片段 AUTH-001-A（管理页面入口），行号从其代码块第一行起计。
```php
<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Vulnerability: Authorisation Bypass' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'authbypass';
$page[ 'help_button' ]   = 'authbypass';
$page[ 'source_button' ] = 'authbypass';
dvwaDatabaseConnect();

$method            = 'GET';
$vulnerabilityFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;
	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;
	case 'high':
		$vulnerabilityFile = 'high.php';
		break;
	default:
		$vulnerabilityFile = 'impossible.php';
		$method = 'POST';
		break;
}

require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/authbypass/source/{$vulnerabilityFile}";

$page[ 'body' ] .= '
<div class="body_padded">
	<h1>Vulnerability: Authorisation Bypass</h1>

	<p>This page should only be accessible by the admin user. Your challenge is to gain access to the features using one of the other users, for example <i>gordonb</i> / <i>abc123</i>.</p>

	<div class="vulnerable_code_area">
	<div style="font-weight: bold;color: red;font-size: 120%;" id="save_result"></div>
	<div id="user_form"></div>
	<p>
		Welcome to the user manager, please enjoy updating your user\'s details.
	</p>
	';

$page[ 'body' ] .= "
<script src='authbypass.js'></script>

<table id='user_table'>
	<thead>
		<th>ID</th>
		<th>First Name</th>
		<th>Surname</th>
		<th>Update</th>
	</thead>
	<tbody>
	</tbody>
</table>

<script>
	populate_form();
</script>
";

$page[ 'body' ] .= '
		' . 
		$html
		. '
	</div>
</div>';

dvwaHtmlEcho( $page );

?>
```

关联片段 AUTH-001-B（浏览器请求与显示），行号从其代码块第一行起计。
```javascript
function show_save_result (data) {
	if (data.result == 'ok') {
		document.getElementById('save_result').innerText = 'Save Successful';
	} else {
		document.getElementById('save_result').innerText = 'Save Failed';
	}
}
	
function submit_change(id) {
	first_name = document.getElementById('first_name_' + id).value
	surname = document.getElementById('surname_' + id).value

	fetch('change_user_details.php', {
		method: 'POST',
		headers: {
			'Accept': 'application/json',
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ 'id': id, 'first_name': first_name, 'surname': surname })
	}
	)
	.then((response) => response.json())
	.then((data) => show_save_result(data));
}

function populate_form() {
	var xhr= new XMLHttpRequest();
	xhr.open('GET', 'get_user_data.php', true);
	xhr.onreadystatechange= function() {
		if (this.readyState!==4) {
			return;
		}
		if (this.status!==200) {
			return;
		}
		const users = JSON.parse (this.responseText);
		table_body = document.getElementById('user_table').getElementsByTagName('tbody')[0];
		users.forEach(updateTable);

		function updateTable (user) {
			var row = table_body.insertRow(0);
			var cell0 = row.insertCell(-1);
			cell0.innerHTML = user['user_id'] + '<input type="hidden" id="user_id_' + user['user_id'] + '" name="user_id" value="' + user['user_id'] + '" />';
			var cell1 = row.insertCell(1);
			cell1.innerHTML = '<input type="text" id="first_name_' + user['user_id'] + '" name="first_name" value="' + user['first_name'] + '" />';
			var cell2 = row.insertCell(2);
			cell2.innerHTML = '<input type="text" id="surname_' + user['user_id'] + '" name="surname" value="' + user['surname'] + '" />';
			var cell3 = row.insertCell(3);
			cell3.innerHTML = '<input type="button" value="Update" onclick="submit_change(' + user['user_id'] + ')" />';
		}
	};
	xhr.send();
}
```

关联片段 AUTH-001-C（被包含的页面角色检查），行号从其代码块第一行起计。
```php
<?php
if (dvwaCurrentUser() != "admin") {
	print "Unauthorised";
	http_response_code(403);
	exit;
}
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
