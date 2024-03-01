rule SIGNATURE_BASE_Kriskynote_Mar17_2 : FILE
{
	meta:
		description = "Detects Kriskynote Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "704baf41-9718-537f-9456-381a9f42fb97"
		date = "2017-03-03"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_kriskynote.yar#L32-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4a1a7c1c75cc64df32d2f055538c5ad15418802733046471520c372a616f1e11"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cb9a2f77868b28d98e4f9c1b27b7242fec2f2abbc91bfc21fe0573e472c5dfcb"

	strings:
		$s1 = "fgjfcn8456fgjhfg89653wetwts" fullword ascii
		$op0 = { 33 c0 80 34 30 03 40 3d e6 21 00 00 72 f4 b8 e6 }

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them )
}
