rule SIGNATURE_BASE_Equationdrug_HDDSSD_Op
{
	meta:
		description = "EquationDrug - HDD/SSD firmware operation - nls_933w.dll"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "e2698f10-49e8-55da-bddc-e5c887f11bc7"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/spy_equation_fiveeyes.yar#L404-L416"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
		logic_hash = "9b45b2016a15f22079c439ff33c20e49d3c846fb4dd83caf2880767ea513a6e3"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "nls_933w.dll" fullword ascii

	condition:
		all of them
}
