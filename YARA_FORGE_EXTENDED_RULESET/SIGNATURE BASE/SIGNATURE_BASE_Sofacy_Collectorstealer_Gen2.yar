rule SIGNATURE_BASE_Sofacy_Collectorstealer_Gen2 : FILE
{
	meta:
		description = "File collectors / USB stealers - Generic"
		author = "Florian Roth (Nextron Systems)"
		id = "03ced94f-de20-56c5-bf17-1ec7d8610684"
		date = "2015-12-04"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_dec15.yar#L99-L116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e917166adf6e1135444f327d8fff6ec6c6a8606d65dda4e24c2f416d23b69d45"
		hash = "92dcb0d8394d0df1064e68d90cd90a6ae5863e91f194cbaac85ec21c202f581f"
		hash = "b1f2d461856bb6f2760785ee1af1a33c71f84986edf7322d3e9bd974ca95f92d"
		logic_hash = "2086b4119bae17ec984665ea1e49d5f496a2cf6bf05ab507fe0cfb6e28039349"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "msdetltemp.dll" fullword ascii
		$s2 = "msdeltemp.dll" fullword wide
		$s3 = "Delete Temp Folder Service" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 2 of them
}
