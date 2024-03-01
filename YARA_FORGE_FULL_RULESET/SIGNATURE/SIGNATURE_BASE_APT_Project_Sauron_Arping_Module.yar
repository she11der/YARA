rule SIGNATURE_BASE_APT_Project_Sauron_Arping_Module
{
	meta:
		description = "Detects strings from arping module - Project Sauron report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "42389511-de92-57cb-9dee-9f829fd5e55a"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L41-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d87e91441994c4ed863596d79c108c9f72adfb708f885cb63a881eb25aa089b7"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Resolve hosts that answer"
		$s2 = "Print only replying Ips"
		$s3 = "Do not display MAC addresses"

	condition:
		all of them
}
