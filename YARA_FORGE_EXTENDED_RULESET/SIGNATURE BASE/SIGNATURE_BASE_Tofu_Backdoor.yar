rule SIGNATURE_BASE_Tofu_Backdoor
{
	meta:
		description = "Detects Tofu Trojan"
		author = "Cylance"
		id = "03848366-f139-5352-959d-390992d96296"
		date = "2017-02-28"
		modified = "2023-12-05"
		reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ham_tofu_chches.yar#L11-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "67c49456dbe4dc4c8bc54139ce6d493ea5588392d8c64010d029d7a63ac7f976"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "Cookies: Sym1.0"
		$b = "\\\\.\\pipe\\1[12345678]"
		$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}

	condition:
		$a or $b or $c
}
