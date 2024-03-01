rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Shell : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "fdfc3fc1-9400-533b-978b-1a1fac112e1f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L1031-L1047"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b7b34215c2293ace70fc06cbb9ce73743e867289"
		logic_hash = "be3961d6568acfaadfa09efda2f914259a59f4e30725c7d434e89f6020e40515"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
		$s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
		$s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii

	condition:
		filesize <1KB and all of them
}
