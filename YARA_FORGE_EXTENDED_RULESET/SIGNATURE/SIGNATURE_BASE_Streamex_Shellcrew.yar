rule SIGNATURE_BASE_Streamex_Shellcrew
{
	meta:
		description = "Detects a "
		author = "Cylance"
		id = "217077bb-71b7-5cbf-8adf-68a16688c415"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_shellcrew_streamex.yar#L11-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a82ff51c1dcd1ebe3d7acc96b46b0b79dcead9146204f060f5413c4c7b5286d3"
		score = 80
		quality = 85
		tags = ""

	strings:
		$a = "0r+8DQY97XGB5iZ4Vf3KsEt61HLoTOuIqJPp2AlncRCgSxUWyebhMdmzvFjNwka="
		$b = {34 ?? 88 04 11 48 63 C3 48 FF C1 48 3D D8 03 00 00}
		$bb = {81 86 ?? ?? 00 10 34 ?? 88 86 ?? ?? 00 10 46 81 FE D8 03 00 00}
		$c = "greendll"
		$d = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36" wide
		$f = {26 5E 25 24 23 91 91 91 91}
		$g = "D:\\pdb\\ht_d6.pdb"

	condition:
		$a or $b or $bb or ($c and $d) or $f or $g
}
