rule SIGNATURE_BASE_Byshell063_Ntboot_2
{
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "9bcb401d-619b-54b8-be51-f0e3b6eb096c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8794-L8805"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
		logic_hash = "25df29000bb410c0ba1fec78920124f6eedbc2585541536239522d2b116270ab"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"

	condition:
		all of them
}
