rule BINARYALERT_Hacktool_Multi_Ncc_ABPTTS
{
	meta:
		description = "Allows for TCP tunneling over HTTP"
		author = "@mimeframe"
		id = "dd5f6316-9e51-5cc8-b293-dc33b09cc801"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://github.com/nccgroup/ABPTTS"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/multi/hacktool_multi_ncc_ABPTTS.yara#L1-L19"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "09874b1d997ac193ad1afa0226f6fb22836c8720c0599d773b18072b92a3acc4"
		score = 75
		quality = 80
		tags = ""

	strings:
		$s1 = "---===[[[ A Black Path Toward The Sun ]]]===---" ascii wide
		$s2 = "https://vulnerableserver/EStatus/" ascii wide
		$s3 = "Error: no ABPTTS forwarding URL was specified. This utility will now exit." ascii wide
		$s4 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" fullword ascii wide
		$s5 = "63688c4f211155c76f2948ba21ebaf83" fullword ascii wide
		$s6 = "ABPTTSClient-log.txt" fullword ascii wide

	condition:
		any of them
}
