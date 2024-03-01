rule SIGNATURE_BASE_OPCLEAVER_Pvz_Out
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "46b51bff-dfd9-5f56-897c-422112bc837b"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L238-L252"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "849300c32d2df42a011386903495d271810fd8a40c76d1a0c6295c059deb3a05"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "Network Connectivity Module" wide
		$s2 = "OSPPSVC" wide

	condition:
		all of them
}
