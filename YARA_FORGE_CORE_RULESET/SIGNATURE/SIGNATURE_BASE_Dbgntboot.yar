rule SIGNATURE_BASE_Dbgntboot
{
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "6b9381e6-597d-5e74-a318-9931d20a9d08"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8130-L8142"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
		logic_hash = "10f86f18aff4995928efb3c8000eca166fe37e6006de7938139cad718ff7653f"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"

	condition:
		all of them
}
