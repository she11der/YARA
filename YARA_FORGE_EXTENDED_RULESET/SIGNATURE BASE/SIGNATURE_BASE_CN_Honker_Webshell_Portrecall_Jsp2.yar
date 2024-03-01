rule SIGNATURE_BASE_CN_Honker_Webshell_Portrecall_Jsp2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "cd34cb47-c5e0-5094-a501-6a8a00d94018"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L688-L704"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "412ed15eb0d24298ba41731502018800ffc24bfc"
		logic_hash = "1ec77a1b0d30cdebce1b5b07445247016230b733a594d8d1de642c2c8af63031"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii
		$s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii
		$s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii

	condition:
		filesize <23KB and all of them
}
