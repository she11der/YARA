rule SIGNATURE_BASE_OPCLEAVER_Wndtest
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "f8daa0a8-f0f0-5bf7-b9ab-eaf5335ff2b9"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L254-L269"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "3b29c2b92b816bd0559695cb6b0b6e050ca8c5e256ec92448535fe9edf20757f"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "[Alt]" wide
		$s2 = "<< %s >>:" wide
		$s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"

	condition:
		all of them
}
