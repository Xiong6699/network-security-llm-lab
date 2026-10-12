<?php
if (dvwaCurrentUser() != "admin") {
	print "Unauthorised";
	http_response_code(403);
	exit;
}
?>
