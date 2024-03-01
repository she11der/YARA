rule SIGNATURE_BASE_CN_Honker_Webshell_Serv_U_2_Admin_By_Lake2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "8fce8835-a4ed-58df-a725-0c1fc04becaa"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L600-L617"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb8039f213e611ab2687edd23e63956c55f30578"
		logic_hash = "a67c08b3a4bed2385d2fa8c007615bfb37a2d739cc13ee2e0f5eda00536b6ea8"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii
		$s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii
		$s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii
		$s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii

	condition:
		filesize <17KB and 2 of them
}
