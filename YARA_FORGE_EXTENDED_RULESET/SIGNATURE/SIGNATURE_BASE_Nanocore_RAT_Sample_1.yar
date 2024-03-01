rule SIGNATURE_BASE_Nanocore_RAT_Sample_1 : FILE
{
	meta:
		description = "Detetcs a certain Nanocore RAT sample"
		author = "Florian Roth (Nextron Systems)"
		id = "381d3caf-77de-544c-869c-4d9f0cae148f"
		date = "2016-04-22"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_nanocore_rat.yar#L46-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "c74e5fe7e9d4dd7f032281b0e617f2355bc5844acf04a8ffbfd42165c7d9b8e4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"

	strings:
		$x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
		$x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
		$x3 = "popthatkitty.Resources.resources" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*))) or ( all of them )
}
