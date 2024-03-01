rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php7 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "f21bb0db-d18a-58c0-a227-5baf5536c57b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1049-L1064"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
		logic_hash = "70804d914c6f31422632943bf663f997eb747a290a13b27bfcc66bc3129f136d"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii
		$s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii

	condition:
		filesize <300KB and all of them
}
