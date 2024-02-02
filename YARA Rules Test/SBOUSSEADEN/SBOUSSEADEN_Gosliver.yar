rule SBOUSSEADEN_Gosliver
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "eba5043a-ca4d-5c5d-a895-51218b03e59e"
		date = "2020-10-11"
		modified = "2020-10-11"
		reference = "https://github.com/BishopFox/sliver"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_sliver_go_framwwork.yara#L2-L9"
		license_url = "N/A"
		logic_hash = "8dc96e533adc29c78a998d9f064ff294d2ef8a4ff00cef8b0c81ef465ef70b08"
		score = 75
		quality = 75
		tags = ""

	strings:
		$go = "_cgo_"

	condition:
		#go>10 and pe.exports("RunSliver")
}