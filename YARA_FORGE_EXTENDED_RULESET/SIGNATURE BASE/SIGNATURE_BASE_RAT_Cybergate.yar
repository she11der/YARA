rule SIGNATURE_BASE_RAT_Cybergate
{
	meta:
		description = "Detects CyberGate RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "387e7c89-c766-54cf-aac0-3ba03092bc25"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/CyberGate"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L230-L254"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6b3861ae5e6bd6478e9d8024b0e67a3ac1dbf31083b77477364c55b51d0ed9b5"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}
