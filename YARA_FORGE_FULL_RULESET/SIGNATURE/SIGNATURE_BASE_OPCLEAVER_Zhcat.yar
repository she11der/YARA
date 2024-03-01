rule SIGNATURE_BASE_OPCLEAVER_Zhcat
{
	meta:
		description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "e1f1bc48-b895-5e23-8ffd-b6ea9c8eb26f"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L271-L285"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ef5112532ba62cb2cf6a1c62b344d9146c5b8e2da50990c8cfd60d91b99bcb5e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
		$s2 = "ABC ( A Big Company )" wide fullword

	condition:
		all of them
}
