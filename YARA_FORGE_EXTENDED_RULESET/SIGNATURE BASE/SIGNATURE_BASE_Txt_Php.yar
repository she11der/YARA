rule SIGNATURE_BASE_Txt_Php : FILE
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "65d5c46f-006d-58f9-bb7f-0a2e1f1853bd"
		date = "2015-06-14"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L445-L461"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
		logic_hash = "ace26e7c0dca285febf6b9192cbe59cc7e55e80f2f4e1a99aba25afcbeadeec1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
		$s2 = "gzuncompress($_SESSION['api']),null);" ascii
		$s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
		$s4 = "if(empty($_SESSION['api']))" fullword ascii

	condition:
		filesize <1KB and all of them
}
