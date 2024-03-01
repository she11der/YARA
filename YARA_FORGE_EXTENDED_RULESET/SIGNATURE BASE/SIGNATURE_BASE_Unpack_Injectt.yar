rule SIGNATURE_BASE_Unpack_Injectt
{
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "80dc3086-41a6-5e30-bbf4-463500fe5e33"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7121-L7134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8a5d2158a566c87edc999771e12d42c5"
		logic_hash = "d8e9ed4f2604617bd6410f36ab827affa3cc6729ba996d0d9cd9c8eb0fd96533"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "%s -Run                              -->To Install And Run The Service"
		$s3 = "%s -Uninstall                        -->To Uninstall The Service"
		$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"

	condition:
		all of them
}
