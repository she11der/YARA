rule SIGNATURE_BASE_OPCLEAVER_Shellcreator2
{
	meta:
		description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
		author = "Cylance Inc."
		id = "b62336c3-39e5-55f8-98df-6c2a2cb0764a"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L68-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5422cf4e4809c1183c3c9870d9a5ddcf806082d8cae81a014255f5f18576101d"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "ShellCreator2.Properties"
		$s2 = "set_IV"

	condition:
		all of them
}
