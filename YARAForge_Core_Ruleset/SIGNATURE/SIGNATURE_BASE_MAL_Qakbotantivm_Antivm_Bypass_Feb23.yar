rule SIGNATURE_BASE_MAL_Qakbotantivm_Antivm_Bypass_Feb23
{
	meta:
		description = "QakBot AntiVM bypass"
		author = "kevoreilly"
		id = "7446522a-788a-512d-ad68-2fcc56169f5a"
		date = "2023-02-17"
		modified = "2023-12-05"
		reference = "https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/mal_qbot_feb23.yar#L40-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "e269497ce458b21c8427b3f6f6594a25d583490930af2d3395cb013b20d08ff7"
		logic_hash = "20f1cd28f38945a3aa328e77e78525fb1ffc47ecf54d5a40c2f18264c3973989"
		score = 75
		quality = 85
		tags = ""
		cape_options = "bp0=$antivm1,action0=unwind,count=1"

	strings:
		$antivm1 = {55 8B EC 3A E4 0F [2] 00 00 00 6A 04 58 3A E4 0F [2] 00 00 00 C7 44 01 [5] 81 44 01 [5] 66 3B FF 74 ?? 6A 04 58 66 3B ED 0F [2] 00 00 00 C7 44 01 [5] 81 6C 01 [5] EB}

	condition:
		all of them
}