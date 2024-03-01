rule SIGNATURE_BASE_Glassrat
{
	meta:
		description = "Detects GlassRAT by RSA (modified by Florian Roth - speed improvements)"
		author = "RSA RESEARCH"
		id = "7739d1f6-f16d-5599-9388-a1d89dbeb355"
		date = "2015-11-03"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_glassRAT.yar#L8-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "939d2cb11ff414641f68b2913fe8d24458e1fd7ba450b8781072bb10da3ad039"
		score = 75
		quality = 85
		tags = ""
		Info = "GlassRat"

	strings:
		$bin1 = {85 C0 B3 01}
		$bin3 = {68 4C 50 00 10}
		$bin4 = {68 48 50 00 10}
		$bin5 = {68 44 50 00 10}
		$hs = {CB FF 5D C9 AD 3F 5B A1 54 13 FE FB 05 C6 22}
		$s1 = "pwlfnn10,gzg"
		$s2 = "AddNum"
		$s3 = "ServiceMain"
		$s4 = "The Window"
		$s5 = "off.dat"

	condition:
		all of ($bin*) and $hs and 3 of ($s*)
}
