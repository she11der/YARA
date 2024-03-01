import "pe"

rule SIGNATURE_BASE_WCE_Modified_1_1014
{
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		author = "Florian Roth (Nextron Systems)"
		id = "536d1a7f-bda1-5c22-bf72-a177468e7c42"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L738-L752"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		logic_hash = "f094d635aabea9b9101fad3d0d23ad37692317ae5b4f636296ee612752c4421f"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "LSASS.EXE" fullword ascii
		$s1 = "_CREDS" ascii
		$s9 = "Using WCE " ascii

	condition:
		all of them
}
