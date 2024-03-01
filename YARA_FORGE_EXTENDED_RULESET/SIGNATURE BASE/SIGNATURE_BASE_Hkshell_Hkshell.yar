rule SIGNATURE_BASE_Hkshell_Hkshell
{
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7436cd7c-7027-56dc-bb62-fac0f70c27d8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7314-L7327"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "168cab58cee59dc4706b3be988312580"
		logic_hash = "bee4d4c957ede41c771d690d52ac2fd3655238cc1fc106d30fb2721084b38aa1"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"

	condition:
		all of them
}
