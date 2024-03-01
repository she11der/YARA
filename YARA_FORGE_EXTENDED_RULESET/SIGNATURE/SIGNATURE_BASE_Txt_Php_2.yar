rule SIGNATURE_BASE_Txt_Php_2 : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file php.html"
		author = "Florian Roth (Nextron Systems)"
		id = "66916e32-9471-54bd-944e-bb751b38d3b0"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L532-L552"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
		logic_hash = "c08f62c3d468c2ebacd10fff6aa0c63bd303d627d487c070a9d22419bf6906cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
		$s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
		$s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
		$s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
		$s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
		$s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
		$s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
		$s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii

	condition:
		filesize <100KB and 4 of them
}
