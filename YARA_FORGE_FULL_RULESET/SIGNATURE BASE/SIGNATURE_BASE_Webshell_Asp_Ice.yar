rule SIGNATURE_BASE_Webshell_Asp_Ice
{
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L507-L520"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d141e011a92f48da72728c35f1934a2b"
		logic_hash = "524419e802d3cb6ac310565af22ec28044984aa4b1b2ee1cfbd292afd071709c"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"

	condition:
		all of them
}
