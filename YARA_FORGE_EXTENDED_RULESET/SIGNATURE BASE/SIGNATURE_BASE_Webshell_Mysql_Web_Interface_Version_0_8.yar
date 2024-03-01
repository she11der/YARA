rule SIGNATURE_BASE_Webshell_Mysql_Web_Interface_Version_0_8
{
	meta:
		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L843-L856"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
		logic_hash = "680d4368804ad21e46dbe400563beca3ef724711b5432dccce1276ecadc04f2c"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"

	condition:
		all of them
}
