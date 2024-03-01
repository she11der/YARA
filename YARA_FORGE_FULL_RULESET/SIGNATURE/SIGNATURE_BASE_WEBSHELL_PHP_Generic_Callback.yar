import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_Generic_Callback : FILE
{
	meta:
		description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
		date = "2021-01-14"
		modified = "2023-09-18"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L412-L717"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e98889690101b59260e871c49263314526f2093f"
		hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
		hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
		hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
		hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
		hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
		hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
		hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
		hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
		hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
		hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
		hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
		hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
		hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
		hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"
		logic_hash = "e12dec5252a816c10443fe0e0b40b0b9b4a187b32facd8e09e1f057801da25f9"
		score = 60
		quality = -1953
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$gfp1 = "eval(\"return [$serialised_parameter"
		$gfp2 = "$this->assert(strpos($styles, $"
		$gfp3 = "$module = new $_GET['module']($_GET['scope']);"
		$gfp4 = "$plugin->$_POST['action']($_POST['id']);"
		$gfp5 = "$_POST[partition_by]($_POST["
		$gfp6 = "$object = new $_REQUEST['type']($_REQUEST['id']);"
		$gfp7 = "The above example code can be easily exploited by passing in a string such as"
		$gfp8 = "Smarty_Internal_Debug::start_render($_template);"
		$gfp9 = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
		$gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
		$gfp11 = "(eval (getenv \"EPROLOG\")))"
		$gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
		$gfp_tiny3 = "include \"./common.php\";"
		$gfp_tiny4 = "assert('FALSE');"
		$gfp_tiny5 = "assert(false);"
		$gfp_tiny6 = "assert(FALSE);"
		$gfp_tiny7 = "assert('array_key_exists("
		$gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
		$gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
		$gfp_tiny10 = "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
		$m_callback2 = "FILTER_CALLBACK" fullword wide ascii
		$cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
		$cfp2 = "IWPML_Backend_Action_Loader" ascii wide
		$cfp3 = "<?phpclass WPML" ascii
		$gen_bit_sus1 = /:\s{0,20}eval}/ nocase wide ascii
		$gen_bit_sus2 = /\.replace\(\/\w\/g/ nocase wide ascii
		$gen_bit_sus6 = "self.delete"
		$gen_bit_sus9 = "\"cmd /c" nocase
		$gen_bit_sus10 = "\"cmd\"" nocase
		$gen_bit_sus11 = "\"cmd.exe" nocase
		$gen_bit_sus12 = "%comspec%" wide ascii
		$gen_bit_sus13 = "%COMSPEC%" wide ascii
		$gen_bit_sus18 = "Hklm.GetValueNames();" nocase
		$gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
		$gen_bit_sus21 = "\"upload\"" wide ascii
		$gen_bit_sus22 = "\"Upload\"" wide ascii
		$gen_bit_sus23 = "UPLOAD" fullword wide ascii
		$gen_bit_sus24 = "fileupload" wide ascii
		$gen_bit_sus25 = "file_upload" wide ascii
		$gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
		$gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
		$gen_bit_sus30 = "serv-u" wide ascii
		$gen_bit_sus31 = "Serv-u" wide ascii
		$gen_bit_sus32 = "Army" fullword wide ascii
		$gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
		$gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
		$gen_bit_sus35 = "crack" fullword wide ascii
		$gen_bit_sus44 = "<pre>" wide ascii
		$gen_bit_sus45 = "<PRE>" wide ascii
		$gen_bit_sus46 = "shell_" wide ascii
		$gen_bit_sus50 = "bypass" wide ascii
		$gen_bit_sus52 = " ^ $" wide ascii
		$gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
		$gen_bit_sus55 = /\w'\.'\w/ wide ascii
		$gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
		$gen_bit_sus57 = "dumper" wide ascii
		$gen_bit_sus59 = "'cmd'" wide ascii
		$gen_bit_sus60 = "\"execute\"" wide ascii
		$gen_bit_sus61 = "/bin/sh" wide ascii
		$gen_bit_sus62 = "Cyber" wide ascii
		$gen_bit_sus63 = "portscan" fullword wide ascii
		$gen_bit_sus66 = "whoami" fullword wide ascii
		$gen_bit_sus67 = "$password='" fullword wide ascii
		$gen_bit_sus68 = "$password=\"" fullword wide ascii
		$gen_bit_sus69 = "$cmd" fullword wide ascii
		$gen_bit_sus70 = "\"?>\"." fullword wide ascii
		$gen_bit_sus71 = "Hacking" fullword wide ascii
		$gen_bit_sus72 = "hacking" fullword wide ascii
		$gen_bit_sus73 = ".htpasswd" wide ascii
		$gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
		$gen_much_sus7 = "Web Shell" nocase
		$gen_much_sus8 = "WebShell" nocase
		$gen_much_sus3 = "hidded shell"
		$gen_much_sus4 = "WScript.Shell.1" nocase
		$gen_much_sus5 = "AspExec"
		$gen_much_sus14 = "\\pcAnywhere\\" nocase
		$gen_much_sus15 = "antivirus" nocase
		$gen_much_sus16 = "McAfee" nocase
		$gen_much_sus17 = "nishang"
		$gen_much_sus18 = "\"unsafe" fullword wide ascii
		$gen_much_sus19 = "'unsafe" fullword wide ascii
		$gen_much_sus24 = "exploit" fullword wide ascii
		$gen_much_sus25 = "Exploit" fullword wide ascii
		$gen_much_sus26 = "TVqQAAMAAA" wide ascii
		$gen_much_sus30 = "Hacker" wide ascii
		$gen_much_sus31 = "HACKED" fullword wide ascii
		$gen_much_sus32 = "hacked" fullword wide ascii
		$gen_much_sus33 = "hacker" wide ascii
		$gen_much_sus34 = "grayhat" nocase wide ascii
		$gen_much_sus35 = "Microsoft FrontPage" wide ascii
		$gen_much_sus36 = "Rootkit" wide ascii
		$gen_much_sus37 = "rootkit" wide ascii
		$gen_much_sus38 = "/*-/*-*/" wide ascii
		$gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
		$gen_much_sus40 = "\"e\"+\"v" wide ascii
		$gen_much_sus41 = "a\"+\"l\"" wide ascii
		$gen_much_sus42 = "\"+\"(\"+\"" wide ascii
		$gen_much_sus43 = "q\"+\"u\"" wide ascii
		$gen_much_sus44 = "\"u\"+\"e" wide ascii
		$gen_much_sus45 = "/*//*/" wide ascii
		$gen_much_sus46 = "(\"/*/\"" wide ascii
		$gen_much_sus47 = "eval(eval(" wide ascii
		$gen_much_sus48 = "unlink(__FILE__)" wide ascii
		$gen_much_sus49 = "Shell.Users" wide ascii
		$gen_much_sus50 = "PasswordType=Regular" wide ascii
		$gen_much_sus51 = "-Expire=0" wide ascii
		$gen_much_sus60 = "_=$$_" wide ascii
		$gen_much_sus61 = "_=$$_" wide ascii
		$gen_much_sus62 = "++;$" wide ascii
		$gen_much_sus63 = "++; $" wide ascii
		$gen_much_sus64 = "_.=$_" wide ascii
		$gen_much_sus70 = "-perm -04000" wide ascii
		$gen_much_sus71 = "-perm -02000" wide ascii
		$gen_much_sus72 = "grep -li password" wide ascii
		$gen_much_sus73 = "-name config.inc.php" wide ascii
		$gen_much_sus75 = "password crack" wide ascii
		$gen_much_sus76 = "mysqlDll.dll" wide ascii
		$gen_much_sus77 = "net user" wide ascii
		$gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
		$gen_much_sus81 = /strrev\(['"]/ wide ascii
		$gen_much_sus82 = "PHPShell" fullword wide ascii
		$gen_much_sus821 = "PHP Shell" fullword wide ascii
		$gen_much_sus83 = "phpshell" fullword wide ascii
		$gen_much_sus84 = "PHPshell" fullword wide ascii
		$gen_much_sus87 = "deface" wide ascii
		$gen_much_sus88 = "Deface" wide ascii
		$gen_much_sus89 = "backdoor" wide ascii
		$gen_much_sus90 = "r00t" fullword wide ascii
		$gen_much_sus91 = "xp_cmdshell" fullword wide ascii
		$gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
		$gen_much_sus93 = "eval(\"/*" wide ascii
		$gen_much_sus94 = "http_response_code(404)" wide ascii
		$gif = { 47 49 46 38 }

	condition:
		not ( any of ($gfp*)) and not ( any of ($gfp_tiny*)) and ( any of ($inp*)) and ( not any of ($cfp*) and ( any of ($callback*) or all of ($m_callback*))) and ( filesize <1000 or ($gif at 0 or ( filesize <4KB and (1 of ($gen_much_sus*) or 2 of ($gen_bit_sus*))) or ( filesize <20KB and (2 of ($gen_much_sus*) or 3 of ($gen_bit_sus*))) or ( filesize <50KB and (2 of ($gen_much_sus*) or 4 of ($gen_bit_sus*))) or ( filesize <100KB and (2 of ($gen_much_sus*) or 6 of ($gen_bit_sus*))) or ( filesize <150KB and (3 of ($gen_much_sus*) or 7 of ($gen_bit_sus*))) or ( filesize <500KB and (4 of ($gen_much_sus*) or 8 of ($gen_bit_sus*)))))
}
