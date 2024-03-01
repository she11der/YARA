rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php4 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "82446dff-dd1e-54a8-bb70-570bedc805b5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L961-L975"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "179975f632baff6ee4d674fe3fabc324724fee9e"
		logic_hash = "e625b6d1fd2c1e62306ccae2775ee7b53ddcdd7a6baef55b386dfcd92dc2e764"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "nc -l -vv -p port(" ascii

	condition:
		uint16(0)==0x4850 and filesize <1KB and all of them
}
