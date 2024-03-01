rule SBOUSSEADEN_Mimikatz_Kiwikey
{
	meta:
		description = "hunt for default mimikatz kiwikey"
		author = "SBousseaden"
		id = "3141e679-6e07-5017-9675-4557fb876ebc"
		date = "2020-08-08"
		modified = "2020-08-09"
		reference = "https://github.com/sbousseaden/YaraHunts/"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/kiwikey.yara#L1-L10"
		license_url = "N/A"
		logic_hash = "03745aed838dafad2fc6e190f181141bda31c212af56edb8ba665b86671f8bee"
		score = 75
		quality = 75
		tags = ""

	strings:
		$A = {60 BA 4F CA C7 44 24 ?? DC 46 6C 7A C7 44 24 ?? 03 3C 17 81 C7 44 24 ?? 94 C0 3D F6}
		$B = {48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF D0}

	condition:
		$A and #B>10
}
