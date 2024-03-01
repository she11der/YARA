rule SIGNATURE_BASE_Item_301 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file item-301.php"
		author = "Florian Roth (Nextron Systems)"
		id = "4ee9a089-313f-53c1-8196-1348d721dbf4"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L257-L273"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
		logic_hash = "623e235ff3eb0922fe8aee732144a15bcc0c580229654ae988353176f488b085"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
		$s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
		$s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
		$s4 = "$sURL = $aArg[0];" fullword ascii

	condition:
		filesize <3KB and 3 of them
}
