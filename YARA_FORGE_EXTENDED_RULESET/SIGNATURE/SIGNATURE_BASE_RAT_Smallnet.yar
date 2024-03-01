rule SIGNATURE_BASE_RAT_Smallnet
{
	meta:
		description = "Detects SmallNet RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "aec1f8fd-2806-527e-9d50-422f212864de"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/SmallNet"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L841-L861"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "17a6be371ce0c616cfea0b42a30e6d9118376912002d59790b133c73fd5436a3"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and ( all of ($a*))
}
