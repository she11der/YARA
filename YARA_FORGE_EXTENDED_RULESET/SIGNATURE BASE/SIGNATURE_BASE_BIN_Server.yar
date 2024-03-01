rule SIGNATURE_BASE_BIN_Server
{
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1625b0ee-5f9f-57d8-8333-f175f46d6c59"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8956-L8972"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
		logic_hash = "34f9d78e0f61717fae2945e7a833c2c6d59e28035ee95da2c5d32b4e196bc957"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"

	condition:
		all of them
}
