rule SIGNATURE_BASE_APT_Project_Sauron_Basex_Module
{
	meta:
		description = "Detects strings from basex module - Project Sauron report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "51ef3826-af5c-562b-a1f8-3bf11532ac2d"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L73-L87"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "90cfb58017d62312c56908aca1a48bb7425f5cd51540298ecf65305b46ffb2c8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "64, 64url, 32, 32url or 16."
		$s2 = "Force decoding when input is invalid/corrupt"
		$s3 = "This cruft"

	condition:
		$x1 or 2 of them
}
