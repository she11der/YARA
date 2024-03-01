rule SIGNATURE_BASE_Mimipenguin_SH
{
	meta:
		description = "Detects Mimipenguin Password Extractor - Linux"
		author = "Florian Roth (Nextron Systems)"
		id = "c670f6fe-562d-598f-a73f-45e4ab234f7d"
		date = "2017-04-01"
		modified = "2023-12-05"
		reference = "https://github.com/huntergregal/mimipenguin"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mimipenguin.yar#L8-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5d9827e7adfe667a4a46e23854cac3b63949abcde5709045f0fe65e7b5704265"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
		$s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
		$s3 = "MimiPenguin Results:" ascii

	condition:
		1 of them
}
